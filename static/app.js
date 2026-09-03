/**
 * PhishGuard AI — Dashboard Application Logic
 * Editorial interface connecting to FastAPI endpoints.
 */

const API = '';

// =========================================================================
// State
// =========================================================================
let threatChart = null;
let allResults = [];
let pollingInterval = null;
let selectedEmlFile = null;
let currentResultData = null;

// Presets data without hype
const PRESETS = {
    paypal: `Subject: URGENT: Verify your account information
From: PayPal Support <security@paypal.com.verify-access.xyz>

Dear Customer, 

We detected unauthorized access to your account. Your access will be suspended within 24 hours unless you confirm your identity immediately.

Confirm your account here: http://paypa1.com.malicious.top/secure/login?id=38294

Failure to respond within 48 hours will result in permanent account closure.

PayPal Support Team`,

    microsoft: `Subject: SECURITY ALERT: Unusual activity detected
From: Microsoft Team <account-alerts@acc0unt-verify.tk>

Someone tried to sign in to your Microsoft account from an unrecognized IP address.

Verify your identity: https://acc0unt-verify.tk/microsoft/login

If you do not verify within 24 hours, your account will be disabled.

Microsoft Security Team`,

    dropbox: `Subject: Password expiration notice
From: Dropbox Notice <support@dr0pbox-secure.xyz>

Your Dropbox password expires today. Click below to update your password and maintain access to shared folders.

https://dr0pbox-secure.xyz/password-reset

If you did not request this update, ignore this notification.

Dropbox Support`,

    safe: `Subject: Q3 Engineering Sync and Roadmap Review
From: Jordan Miller <jordan.miller@company.org>

Hi Alex,

The engineering review has been moved to Thursday at 2:00 PM. The slides and preliminary roadmap are attached in the shared drive.

Let me know if you have questions before our sync.

Thanks,
Jordan`,

    nigerian: `Subject: Estate Distribution Fund Notice ($15,000,000 USD)
From: Dr. James Okonkwo <barrister.james@attorney-lagos.biz>

Dear Sir/Madam,

My late client left an estate valued at $15,000,000 USD without an appointed beneficiary. Because you share the same surname, I am reaching out to facilitate the legal transfer of these funds.

Please remit a $500 transfer filing fee to proceed and supply your primary bank account details. Keep this communication strictly confidential.

Regards,
Dr. James Okonkwo`
};

// =========================================================================
// Initialization
// =========================================================================
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    refreshStats();
    refreshResults();
    checkScannerStatus();
    startPolling();
    initDropZone();
});

function startPolling() {
    pollingInterval = setInterval(() => {
        refreshStats();
        refreshResults();
        checkScannerStatus();
    }, 15000);
}

// =========================================================================
// Tab Navigation
// =========================================================================
function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

    if (tab === 'text') {
        document.getElementById('tabBtnText').classList.add('active');
        document.getElementById('paneText').classList.add('active');
    } else if (tab === 'file') {
        document.getElementById('tabBtnFile').classList.add('active');
        document.getElementById('paneFile').classList.add('active');
    } else if (tab === 'train') {
        document.getElementById('tabBtnTrain').classList.add('active');
        document.getElementById('paneTrain').classList.add('active');
    }
}

// =========================================================================
// Presets
// =========================================================================
function loadPreset(key) {
    switchTab('text');
    const input = document.getElementById('analyzeInput');
    if (PRESETS[key]) {
        input.value = PRESETS[key];
        showToast(`Preset loaded: ${key.charAt(0).toUpperCase() + key.slice(1)}`, 'info');
    }
}

// =========================================================================
// Drag & Drop EML File Handler
// =========================================================================
function initDropZone() {
    const dropZone = document.getElementById('dropZone');
    if (!dropZone) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            setEmlFile(files[0]);
        }
    });
}

function handleFileSelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        setEmlFile(files[0]);
    }
}

function setEmlFile(file) {
    if (!file.name.toLowerCase().endsWith('.eml')) {
        showToast('Please select a valid .eml file.', 'error');
        return;
    }
    selectedEmlFile = file;
    const badge = document.getElementById('selectedFileName');
    badge.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    badge.style.display = 'inline-block';
    document.getElementById('analyzeFileBtn').disabled = false;
    showToast(`Loaded ${file.name}`, 'info');
}

function clearFileUpload() {
    selectedEmlFile = null;
    const input = document.getElementById('emlFileInput');
    if (input) input.value = '';
    const badge = document.getElementById('selectedFileName');
    if (badge) badge.style.display = 'none';
    const btn = document.getElementById('analyzeFileBtn');
    if (btn) btn.disabled = true;
    document.getElementById('inlineResult').classList.remove('visible');
}

async function uploadEmlFile() {
    if (!selectedEmlFile) {
        showToast('Please select an .eml file first.', 'error');
        return;
    }

    const btn = document.getElementById('analyzeFileBtn');
    btn.disabled = true;
    btn.textContent = 'Analyzing EML…';

    try {
        const formData = new FormData();
        formData.append('file', selectedEmlFile);

        const res = await fetch(`${API}/analyze`, { method: 'POST', body: formData });
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
        const data = await res.json();

        showInlineResult(data);
        showToast(`Analysis complete: ${data.status}`, data.status === 'Safe' ? 'success' : 'error');
        refreshStats();
        refreshResults();
    } catch (e) {
        showToast('EML analysis failed: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Analyze EML File';
    }
}

// =========================================================================
// Model Retraining
// =========================================================================
async function triggerTraining() {
    const btn = document.getElementById('trainBtn');
    const csvInput = document.getElementById('trainCsvInput');
    const reportArea = document.getElementById('trainReportArea');
    const reportContent = document.getElementById('trainReportContent');

    btn.disabled = true;
    btn.textContent = 'Training Ensemble Model…';

    try {
        const formData = new FormData();
        if (csvInput.files && csvInput.files.length > 0) {
            formData.append('file', csvInput.files[0]);
        }

        const res = await fetch(`${API}/train`, { method: 'POST', body: formData });
        const data = await res.json();

        if (data.status === 'ok') {
            reportArea.style.display = 'block';
            reportContent.textContent = data.report || 'Model retrained successfully.';
            showToast('Model training completed.', 'success');
        } else {
            showToast('Training failed: ' + (data.detail || 'Unknown error'), 'error');
        }
    } catch (e) {
        showToast('Training error: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Retrain Classifier';
    }
}

// =========================================================================
// Copy Report
// =========================================================================
function copyReport() {
    if (!currentResultData) {
        showToast('No active analysis to copy.', 'error');
        return;
    }
    const d = currentResultData;
    let text = `=== PhishGuard Threat Analysis Report ===\n`;
    text += `Verdict: ${d.status}\n`;
    text += `Threat Score: ${d.threat_score.toFixed(1)} / 100\n`;
    text += `Confidence Floor: ${(d.confidence * 100).toFixed(0)}%\n`;
    text += `Action: ${d.action}\n\n`;
    text += `Breakdown:\n`;
    if (d.breakdown) {
        for (const [k, v] of Object.entries(d.breakdown)) {
            text += `  - ${k}: ${v > 0 ? '+' : ''}${v.toFixed(1)}\n`;
        }
    }
    text += `\nEvidence Trail:\n`;
    (d.evidence || []).forEach(e => {
        text += `  [${e.source}] ${e.detail} (${e.contribution > 0 ? '+' : ''}${e.contribution.toFixed(1)})\n`;
    });

    navigator.clipboard.writeText(text).then(() => {
        showToast('Report copied to clipboard.', 'success');
    }).catch(err => {
        showToast('Copy failed: ' + err, 'error');
    });
}

// =========================================================================
// Stats
// =========================================================================
async function refreshStats() {
    try {
        const res = await fetch(`${API}/api/stats`);
        const data = await res.json();
        document.getElementById('statTotal').textContent = data.total;
        document.getElementById('statSafe').textContent = data.safe;
        document.getElementById('statSuspicious').textContent = data.suspicious;
        document.getElementById('statPhishing').textContent = data.phishing;
        updateChart(data);
    } catch (e) {
        console.error('Stats fetch error:', e);
    }
}

// =========================================================================
// Chart.js (Warm Editorial Dark Theme)
// =========================================================================
function initChart() {
    const canvas = document.getElementById('threatChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Suspicious', 'Phishing'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    '#5db872',
                    '#d4a017',
                    '#c64545'
                ],
                borderColor: '#181715',
                borderWidth: 2,
                hoverOffset: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#a09d96',
                        font: { family: 'Inter', size: 12, weight: '500' },
                        padding: 14,
                        usePointStyle: true,
                        pointStyleWidth: 8,
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(24, 23, 21, 0.95)',
                    titleColor: '#faf9f5',
                    bodyColor: '#a09d96',
                    titleFont: { family: 'Inter', weight: '500' },
                    bodyFont: { family: 'Inter' },
                    borderColor: '#2d2b27',
                    borderWidth: 1,
                    cornerRadius: 6,
                    padding: 10,
                }
            }
        }
    });
}

function updateChart(stats) {
    if (!threatChart) return;
    threatChart.data.datasets[0].data = [
        stats.safe || 0,
        stats.suspicious || 0,
        stats.phishing || 0,
    ];
    threatChart.update('none');
}

// =========================================================================
// Text Analysis
// =========================================================================
async function analyzeText() {
    const input = document.getElementById('analyzeInput');
    const btn = document.getElementById('analyzeBtn');
    const text = input.value.trim();

    if (!text) {
        showToast('Paste email content before analyzing.', 'error');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Analyzing Message…';

    try {
        const formData = new FormData();
        formData.append('text', text);

        const res = await fetch(`${API}/analyze/text`, { method: 'POST', body: formData });
        const data = await res.json();

        showInlineResult(data);
        showToast(`Analysis complete: ${data.status}`, data.status === 'Safe' ? 'success' : 'error');
        refreshStats();
        refreshResults();
    } catch (e) {
        showToast('Analysis error: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Analyze Message';
    }
}

function showInlineResult(data) {
    currentResultData = data;
    const container = document.getElementById('inlineResult');
    container.classList.add('visible');

    const statusPill = document.getElementById('inlineStatus');
    statusPill.textContent = data.status;
    statusPill.className = 'status-pill ' + data.status.toLowerCase();

    const score = document.getElementById('inlineScore');
    score.textContent = data.threat_score.toFixed(1);
    score.style.color = getScoreColor(data.threat_score);

    document.getElementById('inlineAction').textContent = data.action;
    document.getElementById('inlineConfidence').textContent = (data.confidence * 100).toFixed(0) + '%';

    // Breakdown Chips
    const breakdownChips = document.getElementById('breakdownChips');
    if (breakdownChips && data.breakdown) {
        breakdownChips.innerHTML = '';
        for (const [key, val] of Object.entries(data.breakdown)) {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            const color = val > 0 ? 'var(--status-phishing)' : val < 0 ? 'var(--status-safe)' : 'var(--muted)';
            const chip = document.createElement('div');
            chip.className = 'breakdown-chip';
            chip.innerHTML = `<span class="breakdown-chip-title">${escapeHtml(label)}</span><span class="breakdown-chip-val" style="color:${color}">${val > 0 ? '+' : ''}${val.toFixed(1)}</span>`;
            breakdownChips.appendChild(chip);
        }
    }

    // Evidence List
    const evidenceList = document.getElementById('inlineEvidence');
    evidenceList.innerHTML = '';
    (data.evidence || []).forEach(ev => {
        const li = document.createElement('li');
        const color = ev.contribution > 0 ? 'var(--status-phishing)' : 'var(--status-safe)';
        li.innerHTML = `<strong>${escapeHtml(ev.source)}</strong>: ${escapeHtml(ev.detail)} <span style="color:${color}; float:right; font-weight:600;">${ev.contribution > 0 ? '+' : ''}${ev.contribution.toFixed(1)}</span>`;
        evidenceList.appendChild(li);
    });
}

function clearAnalysis() {
    document.getElementById('analyzeInput').value = '';
    document.getElementById('inlineResult').classList.remove('visible');
}

function getScoreColor(score) {
    if (score >= 60) return '#c64545';
    if (score >= 35) return '#d4a017';
    return '#5db872';
}

// =========================================================================
// IMAP Scanner Controls
// =========================================================================
async function checkScannerStatus() {
    try {
        const res = await fetch(`${API}/scanner/status`);
        const data = await res.json();
        updateScannerBadge(data.running);
    } catch (e) {
        updateScannerBadge(false);
    }
}

function updateScannerBadge(running) {
    const badge = document.getElementById('scannerBadge');
    const text = document.getElementById('scannerBadgeText');
    const connectBtn = document.getElementById('connectBtn');
    const disconnectBtn = document.getElementById('disconnectBtn');

    if (running) {
        badge.classList.add('active');
        text.textContent = 'Scanner Active';
        if (connectBtn) connectBtn.disabled = true;
        if (disconnectBtn) disconnectBtn.disabled = false;
    } else {
        badge.classList.remove('active');
        text.textContent = 'Scanner Offline';
        if (connectBtn) connectBtn.disabled = false;
        if (disconnectBtn) disconnectBtn.disabled = true;
    }
}

async function connectMail() {
    const host = document.getElementById('mailHost').value.trim();
    const port = parseInt(document.getElementById('mailPort').value) || 993;
    const email = document.getElementById('mailEmail').value.trim();
    const password = document.getElementById('mailPassword').value;
    const folder = document.getElementById('mailFolder').value.trim() || 'INBOX';
    const interval = parseInt(document.getElementById('mailInterval').value) || 30;

    if (!host || !email || !password) {
        showToast('Please provide host, email, and app password.', 'error');
        return;
    }

    const btn = document.getElementById('connectBtn');
    btn.disabled = true;
    btn.textContent = 'Connecting…';

    try {
        const res = await fetch(`${API}/scanner/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host, port, email, password, folder,
                poll_interval: interval,
                quarantine_folder: 'Quarantine'
            })
        });
        const data = await res.json();

        if (res.ok) {
            showToast('Mailbox scanner started.', 'success');
            updateScannerBadge(true);
        } else {
            showToast('Connection failed: ' + (data.detail || 'Unknown error'), 'error');
            updateScannerBadge(false);
        }
    } catch (e) {
        showToast('Connection error: ' + e.message, 'error');
        updateScannerBadge(false);
    } finally {
        btn.textContent = 'Connect & Start Monitoring';
        btn.disabled = false;
    }
}

async function disconnectMail() {
    const btn = document.getElementById('disconnectBtn');
    btn.disabled = true;

    try {
        const res = await fetch(`${API}/scanner/stop`, { method: 'POST' });
        const data = await res.json();
        showToast(data.message || 'Scanner stopped.', 'info');
        updateScannerBadge(false);
    } catch (e) {
        showToast('Error stopping scanner: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
    }
}

// =========================================================================
// Audit Trail Results
// =========================================================================
async function refreshResults() {
    try {
        const res = await fetch(`${API}/api/results?limit=50`);
        allResults = await res.json();
        renderResults(allResults);
    } catch (e) {
        console.error('Results fetch error:', e);
    }
}

function renderResults(results) {
    const tbody = document.getElementById('resultsBody');
    const empty = document.getElementById('emptyState');

    if (!results.length) {
        tbody.innerHTML = '';
        empty.style.display = 'block';
        return;
    }
    empty.style.display = 'none';

    tbody.innerHTML = results.map((r, idx) => {
        const time = formatTime(r.timestamp);
        const statusClass = r.status.toLowerCase();
        const scoreColor = getScoreColor(r.threat_score);
        const sourceClass = r.source === 'imap' ? 'imap' : '';

        return `<tr onclick="showDetail(${idx})">
            <td>${time}</td>
            <td>${escapeHtml(r.sender || '—')}</td>
            <td>${escapeHtml(r.subject || '(no subject)')}</td>
            <td><span class="status-pill ${statusClass}">${r.status}</span></td>
            <td>
                <span class="score-inline" style="color:${scoreColor}">${r.threat_score.toFixed(1)}</span>
            </td>
            <td>${(r.confidence * 100).toFixed(0)}%</td>
            <td><span class="source-badge ${sourceClass}">${r.source}</span></td>
        </tr>`;
    }).join('');
}

// =========================================================================
// Detail Modal
// =========================================================================
function showDetail(idx) {
    const r = allResults[idx];
    if (!r) return;

    document.getElementById('modalTitle').textContent = r.subject || '(no subject)';

    let html = `
        <div class="detail-row"><span class="label">Sender</span><span>${escapeHtml(r.sender || '—')}</span></div>
        <div class="detail-row"><span class="label">Status</span><span class="status-pill ${r.status.toLowerCase()}">${r.status}</span></div>
        <div class="detail-row"><span class="label">Threat Score</span><span style="color:${getScoreColor(r.threat_score)};font-weight:600">${r.threat_score.toFixed(1)} / 100</span></div>
        <div class="detail-row"><span class="label">Confidence</span><span>${(r.confidence * 100).toFixed(0)}%</span></div>
        <div class="detail-row"><span class="label">Action</span><span>${escapeHtml(r.action)}</span></div>
        <div class="detail-row"><span class="label">Source</span><span class="source-badge ${r.source === 'imap' ? 'imap' : ''}">${r.source}</span></div>
        <div class="detail-row"><span class="label">Time</span><span>${formatTime(r.timestamp)}</span></div>
    `;

    if (r.breakdown) {
        html += `<div style="margin-top:16px;"><span class="breakdown-title">Score Breakdown</span><div class="breakdown-chips">`;
        for (const [key, val] of Object.entries(r.breakdown)) {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            const color = val > 0 ? 'var(--status-phishing)' : val < 0 ? 'var(--status-safe)' : 'var(--muted)';
            html += `<div class="breakdown-chip"><span class="breakdown-chip-title">${label}</span><span class="breakdown-chip-val" style="color:${color}">${val > 0 ? '+' : ''}${val.toFixed(1)}</span></div>`;
        }
        html += `</div></div>`;
    }

    if (r.evidence && r.evidence.length) {
        html += `<div style="margin-top:16px;"><span class="breakdown-title">Evidence Trail</span><ul class="evidence-list" style="margin-top:8px;">`;
        r.evidence.forEach(ev => {
            const color = ev.contribution > 0 ? 'var(--status-phishing)' : 'var(--status-safe)';
            html += `<li><strong>${escapeHtml(ev.source)}</strong>: ${escapeHtml(ev.detail)} <span style="color:${color}; float:right; font-weight:600;">${ev.contribution > 0 ? '+' : ''}${ev.contribution.toFixed(1)}</span></li>`;
        });
        html += `</ul></div>`;
    }

    if (r.body_preview) {
        html += `<div style="margin-top:16px;"><span class="breakdown-title">Message Body Preview</span><pre class="text-input" style="white-space:pre-wrap; font-family:var(--font-mono); font-size:12px; margin-top:6px; max-height:160px; overflow-y:auto;">${escapeHtml(r.body_preview)}</pre></div>`;
    }

    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('detailModal').classList.add('visible');
}

function closeModal() {
    document.getElementById('detailModal').classList.remove('visible');
}

document.getElementById('detailModal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('detailModal')) closeModal();
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

// =========================================================================
// Toast Notification System
// =========================================================================
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(12px)';
        setTimeout(() => toast.remove(), 250);
    }, 3500);
}

// =========================================================================
// Utilities
// =========================================================================
function formatTime(isoStr) {
    if (!isoStr) return '—';
    try {
        const d = new Date(isoStr);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
            ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
        return isoStr;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
