/**
 * PhishGuard AI — Dashboard Application Logic
 * Handles stats polling, manual analysis, mail scanner controls,
 * results table rendering, and Chart.js visualization.
 */

const API = '';  // Same origin

// =========================================================================
// State
// =========================================================================
let threatChart = null;
let allResults = [];
let pollingInterval = null;

// =========================================================================
// Initialization
// =========================================================================
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    refreshStats();
    refreshResults();
    checkScannerStatus();
    startPolling();
});

function startPolling() {
    pollingInterval = setInterval(() => {
        refreshStats();
        refreshResults();
        checkScannerStatus();
    }, 5000);
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
// Chart
// =========================================================================
function initChart() {
    const ctx = document.getElementById('threatChart').getContext('2d');
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Suspicious', 'Phishing'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(16, 185, 129, 0.8)',
                    'rgba(245, 158, 11, 0.8)',
                    'rgba(239, 68, 68, 0.8)',
                ],
                borderColor: [
                    'rgba(16, 185, 129, 1)',
                    'rgba(245, 158, 11, 1)',
                    'rgba(239, 68, 68, 1)',
                ],
                borderWidth: 2,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Inter', size: 12, weight: '500' },
                        padding: 16,
                        usePointStyle: true,
                        pointStyleWidth: 10,
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    titleFont: { family: 'Inter', weight: '600' },
                    bodyFont: { family: 'Inter' },
                    borderColor: 'rgba(255,255,255,0.08)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12,
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
// Manual Analysis
// =========================================================================
async function analyzeText() {
    const input = document.getElementById('analyzeInput');
    const btn = document.getElementById('analyzeBtn');
    const text = input.value.trim();

    if (!text) {
        showToast('Please paste some email text to analyze.', 'error');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing…';

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
        showToast('Analysis failed: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '🛡️ Analyze';
    }
}

function showInlineResult(data) {
    const container = document.getElementById('inlineResult');
    container.classList.add('visible');

    const statusBadge = document.getElementById('inlineStatus');
    statusBadge.textContent = data.status;
    statusBadge.className = 'status-badge ' + data.status.toLowerCase();

    const score = document.getElementById('inlineScore');
    score.textContent = data.threat_score.toFixed(1);
    score.style.color = getScoreColor(data.threat_score);

    document.getElementById('inlineAction').textContent = data.action;
    document.getElementById('inlineConfidence').textContent = (data.confidence * 100).toFixed(0) + '%';

    const evidenceList = document.getElementById('inlineEvidence');
    evidenceList.innerHTML = '';
    (data.evidence || []).forEach(ev => {
        const li = document.createElement('li');
        li.innerHTML = `<strong style="color:var(--accent-cyan)">${escapeHtml(ev.source)}</strong>: ${escapeHtml(ev.detail)} <span style="color:${ev.contribution > 0 ? 'var(--status-phishing)' : 'var(--status-safe)'}; float:right; font-weight:600;">${ev.contribution > 0 ? '+' : ''}${ev.contribution.toFixed(1)}</span>`;
        evidenceList.appendChild(li);
    });
}

function clearAnalysis() {
    document.getElementById('analyzeInput').value = '';
    document.getElementById('inlineResult').classList.remove('visible');
}

// =========================================================================
// Mail Scanner
// =========================================================================
async function connectMail() {
    const btn = document.getElementById('connectBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Connecting…';

    const config = {
        imap_host: document.getElementById('mailHost').value,
        imap_port: parseInt(document.getElementById('mailPort').value) || 993,
        email: document.getElementById('mailEmail').value,
        password: document.getElementById('mailPassword').value,
        folder: document.getElementById('mailFolder').value || 'INBOX',
        poll_interval: parseInt(document.getElementById('mailInterval').value) || 30,
    };

    if (!config.email || !config.password) {
        showToast('Please enter your email and app password.', 'error');
        btn.disabled = false;
        btn.innerHTML = '▶ Connect & Start Scanning';
        return;
    }

    try {
        const res = await fetch(`${API}/api/mail/connect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config),
        });
        const data = await res.json();
        if (data.status === 'ok') {
            showToast('Mail scanner connected and running!', 'success');
            document.getElementById('disconnectBtn').disabled = false;
            updateScannerBadge(true);
        } else {
            showToast('Connection failed: ' + (data.detail || 'Unknown error'), 'error');
            btn.disabled = false;
        }
    } catch (e) {
        showToast('Connection error: ' + e.message, 'error');
        btn.disabled = false;
    }
    btn.innerHTML = '▶ Connect & Start Scanning';
}

async function disconnectMail() {
    try {
        await fetch(`${API}/api/mail/disconnect`, { method: 'POST' });
        showToast('Mail scanner stopped.', 'info');
        document.getElementById('connectBtn').disabled = false;
        document.getElementById('disconnectBtn').disabled = true;
        updateScannerBadge(false);
    } catch (e) {
        showToast('Error stopping scanner: ' + e.message, 'error');
    }
}

async function checkScannerStatus() {
    try {
        const res = await fetch(`${API}/api/mail/status`);
        const data = await res.json();
        updateScannerBadge(data.running);
        if (data.running) {
            document.getElementById('connectBtn').disabled = true;
            document.getElementById('disconnectBtn').disabled = false;
        }
    } catch (e) {
        // Server might not be up yet
    }
}

function updateScannerBadge(active) {
    const badge = document.getElementById('scannerBadge');
    const text = document.getElementById('scannerBadgeText');
    if (active) {
        badge.classList.add('active');
        text.textContent = 'Scanner Active';
    } else {
        badge.classList.remove('active');
        text.textContent = 'Scanner Offline';
    }
}

// =========================================================================
// Results Table
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
        const scorePct = Math.min(r.threat_score, 100);
        const sourceClass = r.source === 'imap' ? 'imap' : '';

        return `<tr onclick="showDetail(${idx})">
            <td>${time}</td>
            <td>${escapeHtml(r.sender || '—')}</td>
            <td>${escapeHtml(r.subject || '(no subject)')}</td>
            <td><span class="status-badge ${statusClass}">${r.status}</span></td>
            <td>
                <div class="score-bar-cell">
                    <span style="color:${scoreColor};font-weight:600;min-width:32px;">${r.threat_score.toFixed(1)}</span>
                    <div class="score-bar">
                        <div class="score-bar-fill" style="width:${scorePct}%;background:${scoreColor}"></div>
                    </div>
                </div>
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
        <div class="detail-row"><span class="label">Status</span><span class="status-badge ${r.status.toLowerCase()}">${r.status}</span></div>
        <div class="detail-row"><span class="label">Threat Score</span><span style="color:${getScoreColor(r.threat_score)};font-weight:700">${r.threat_score.toFixed(1)} / 100</span></div>
        <div class="detail-row"><span class="label">Confidence</span><span>${(r.confidence * 100).toFixed(0)}%</span></div>
        <div class="detail-row"><span class="label">Action</span><span>${escapeHtml(r.action)}</span></div>
        <div class="detail-row"><span class="label">Source</span><span class="source-badge ${r.source === 'imap' ? 'imap' : ''}">${r.source}</span></div>
        <div class="detail-row"><span class="label">Time</span><span>${formatTime(r.timestamp)}</span></div>
    `;

    // Breakdown
    if (r.breakdown) {
        html += `<div class="evidence-list"><h4>Score Breakdown</h4>`;
        for (const [key, val] of Object.entries(r.breakdown)) {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            const color = val > 0 ? 'var(--status-phishing)' : val < 0 ? 'var(--status-safe)' : 'var(--text-muted)';
            html += `<div class="evidence-item"><span class="ev-source">${label}</span><span class="ev-contribution" style="color:${color}">${val > 0 ? '+' : ''}${val.toFixed(1)}</span></div>`;
        }
        html += `</div>`;
    }

    // Evidence
    if (r.evidence && r.evidence.length) {
        html += `<div class="evidence-list"><h4>Evidence Trail</h4>`;
        r.evidence.forEach(ev => {
            const color = ev.contribution > 0 ? 'var(--status-phishing)' : ev.contribution < 0 ? 'var(--status-safe)' : 'var(--text-muted)';
            html += `<div class="evidence-item">
                <span class="ev-source">${escapeHtml(ev.source)}</span>
                <span class="ev-contribution" style="color:${color}">${ev.contribution > 0 ? '+' : ''}${ev.contribution.toFixed(1)}</span>
                <div class="ev-detail">${escapeHtml(ev.detail)}</div>
            </div>`;
        });
        html += `</div>`;
    }

    // Body preview
    if (r.body_preview) {
        html += `<div class="evidence-list"><h4>Body Preview</h4><div class="evidence-item"><div class="ev-detail" style="white-space:pre-wrap;">${escapeHtml(r.body_preview)}</div></div></div>`;
    }

    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('detailModal').classList.add('visible');
}

function closeModal() {
    document.getElementById('detailModal').classList.remove('visible');
}

// Close modal on overlay click
document.getElementById('detailModal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('detailModal')) closeModal();
});

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

// =========================================================================
// Utilities
// =========================================================================
function getScoreColor(score) {
    if (score >= 75) return '#ef4444';
    if (score >= 45) return '#f59e0b';
    return '#10b981';
}

function formatTime(isoString) {
    if (!isoString) return '—';
    try {
        const d = new Date(isoString + 'Z');
        const now = new Date();
        const diffMs = now - d;
        const diffMin = Math.floor(diffMs / 60000);

        if (diffMin < 1) return 'Just now';
        if (diffMin < 60) return `${diffMin}m ago`;
        const diffHr = Math.floor(diffMin / 60);
        if (diffHr < 24) return `${diffHr}h ago`;

        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
        return isoString;
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { success: '✓', error: '✕', info: 'ℹ' };
    toast.innerHTML = `<span>${icons[type] || 'ℹ'}</span> ${escapeHtml(message)}`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(40px)';
        toast.style.transition = '0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}
