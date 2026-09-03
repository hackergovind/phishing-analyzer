/**
 * PhishGuard AI — Mailbox Defense & Push Notifications Engine
 * Handles IMAP connection, desktop push alerts, audio warning chimes,
 * and live protected inbox monitoring.
 */

const API = '';

// =========================================================================
// State
// =========================================================================
let threatChart = null;
let allResults = [];
let knownResultIds = new Set();
let isInitialLoad = true;
let pollingInterval = null;

// Provider Configurations
const PROVIDERS = {
    gmail: {
        host: 'imap.gmail.com',
        port: 993,
        showHelp: true,
        helpText: 'Gmail requires a 16-character App Password. Normal account passwords are rejected.'
    },
    outlook: {
        host: 'outlook.office365.com',
        port: 993,
        showHelp: false
    },
    yahoo: {
        host: 'imap.mail.yahoo.com',
        port: 993,
        showHelp: false
    },
    custom: {
        host: '',
        port: 993,
        showHelp: false
    }
};

// =========================================================================
// Initialization
// =========================================================================
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    updateNotificationButtonUI();
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
    }, 10000);
}

// =========================================================================
// Push Notification System (Desktop & Browser)
// =========================================================================
function updateNotificationButtonUI() {
    const btn = document.getElementById('notifStatusBtn');
    const grantBtn = document.getElementById('grantNotifBtn');
    const text = document.getElementById('notifBtnText');
    const statusText = document.getElementById('notifCardStatusText');

    if (!('Notification' in window)) {
        if (text) text.textContent = 'Push Unsupported';
        if (btn) btn.disabled = true;
        if (grantBtn) grantBtn.disabled = true;
        if (statusText) statusText.textContent = 'This browser does not support HTML5 desktop notifications.';
        return;
    }

    if (Notification.permission === 'granted') {
        if (text) text.textContent = 'Push Alerts Active';
        if (btn) {
            btn.classList.remove('btn-secondary');
            btn.classList.add('btn-primary');
        }
        if (grantBtn) {
            grantBtn.textContent = '✓ Alerts Enabled';
            grantBtn.disabled = true;
        }
        if (statusText) {
            statusText.textContent = 'Desktop push alerts are enabled. You will be alerted immediately if a phishing email is detected.';
        }
    } else if (Notification.permission === 'denied') {
        if (text) text.textContent = 'Alerts Blocked';
        if (btn) btn.disabled = false;
        if (grantBtn) {
            grantBtn.textContent = 'Unblock in Browser';
            grantBtn.disabled = true;
        }
        if (statusText) {
            statusText.textContent = 'Notifications are blocked in your browser settings. Please allow notifications for this site to receive alerts.';
        }
    } else {
        if (text) text.textContent = 'Enable Push Alerts';
        if (grantBtn) {
            grantBtn.textContent = 'Allow Notifications';
            grantBtn.disabled = false;
        }
    }
}

async function requestNotificationPermission() {
    if (!('Notification' in window)) {
        showToast('Your browser does not support desktop notifications.', 'error');
        return;
    }

    try {
        const permission = await Notification.requestPermission();
        updateNotificationButtonUI();
        if (permission === 'granted') {
            showToast('Desktop push notifications enabled!', 'success');
            playAlertSound(false);
            new Notification('🛡️ PhishGuard Protection Enabled', {
                body: 'You will receive real-time alerts whenever a phishing threat is detected in your mailbox.',
                tag: 'phishguard-welcome'
            });
        } else {
            showToast('Notification permission was not granted.', 'error');
        }
    } catch (e) {
        console.error('Notification error:', e);
    }
}

// Audio Chime (Synthetic Web Audio API — 100% offline & zero external assets)
function playAlertSound(isUrgent = true) {
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return;
        const ctx = new AudioContext();

        const osc = ctx.createOscillator();
        const gain = ctx.createGain();

        osc.connect(gain);
        gain.connect(ctx.destination);

        if (isUrgent) {
            // Urgent double-beep alert for phishing
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(880, ctx.currentTime);
            osc.frequency.setValueAtTime(660, ctx.currentTime + 0.12);
            osc.frequency.setValueAtTime(880, ctx.currentTime + 0.24);

            gain.gain.setValueAtTime(0.3, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.45);

            osc.start(ctx.currentTime);
            osc.stop(ctx.currentTime + 0.45);
        } else {
            // Gentle confirmation chime
            osc.type = 'sine';
            osc.frequency.setValueAtTime(523.25, ctx.currentTime);
            osc.frequency.setValueAtTime(659.25, ctx.currentTime + 0.1);

            gain.gain.setValueAtTime(0.2, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);

            osc.start(ctx.currentTime);
            osc.stop(ctx.currentTime + 0.3);
        }
    } catch (err) {
        console.warn('Audio playback not permitted or unavailable:', err);
    }
}

// Dispatch Push Alert for Phishing
function triggerPhishingAlert(result) {
    playAlertSound(true);

    // 1. Native Desktop Push Notification
    if ('Notification' in window && Notification.permission === 'granted') {
        const title = result.status === 'Phishing'
            ? '⚠️ PHISHING EMAIL QUARANTINED'
            : '⚠️ SUSPICIOUS EMAIL FLAGGED';

        const body = `Sender: ${result.sender || 'Unknown'}\nSubject: ${result.subject || '(no subject)'}\nThreat Score: ${result.threat_score.toFixed(1)}/100\nAction: ${result.action}`;

        const notif = new Notification(title, {
            body: body,
            tag: `phish-${Date.now()}`,
            requireInteraction: true
        });

        notif.onclick = () => {
            window.focus();
            showUrgentAlertModal(result);
            notif.close();
        };
    }

    // 2. In-App Urgent Modal Alert
    showUrgentAlertModal(result);
}

function showUrgentAlertModal(result) {
    const modal = document.getElementById('urgentAlertModal');
    const details = document.getElementById('alertModalDetails');

    details.innerHTML = `
        <div class="alert-item"><strong>Sender:</strong> ${escapeHtml(result.sender || '—')}</div>
        <div class="alert-item"><strong>Subject:</strong> ${escapeHtml(result.subject || '(no subject)')}</div>
        <div class="alert-item"><strong>Threat Score:</strong> <span style="color:var(--status-phishing); font-weight:700;">${result.threat_score.toFixed(1)} / 100</span></div>
        <div class="alert-item"><strong>Status:</strong> ${result.status}</div>
        <div class="alert-item"><strong>Protection Action:</strong> ${escapeHtml(result.action)}</div>
    `;

    modal.classList.add('visible');
}

function closeUrgentAlert() {
    document.getElementById('urgentAlertModal').classList.remove('visible');
}

// Test Alert Simulation
async function sendTestAlert() {
    showToast('Sending simulated phishing alert…', 'info');
    try {
        const res = await fetch(`${API}/api/mail/test-alert`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            triggerPhishingAlert(data.result);
            refreshStats();
            refreshResults();
            showToast('Simulated alert dispatched!', 'success');
        } else {
            showToast('Failed to simulate alert: ' + (data.detail || 'Unknown error'), 'error');
        }
    } catch (e) {
        showToast('Alert simulation error: ' + e.message, 'error');
    }
}

// =========================================================================
// Provider Selection
// =========================================================================
function selectProvider(name) {
    document.querySelectorAll('.preset-chip').forEach(btn => btn.classList.remove('active'));

    const prov = PROVIDERS[name] || PROVIDERS.custom;
    const hostInput = document.getElementById('mailHost');
    const portInput = document.getElementById('mailPort');
    const helpBox = document.getElementById('gmailHelpBox');

    if (hostInput && prov.host) hostInput.value = prov.host;
    if (portInput) portInput.value = prov.port;

    if (name === 'gmail') {
        document.getElementById('provGmail')?.classList.add('active');
        if (helpBox) helpBox.style.display = 'block';
    } else if (name === 'outlook') {
        document.getElementById('provOutlook')?.classList.add('active');
        if (helpBox) helpBox.style.display = 'none';
    } else if (name === 'yahoo') {
        document.getElementById('provYahoo')?.classList.add('active');
        if (helpBox) helpBox.style.display = 'none';
    } else {
        document.getElementById('provCustom')?.classList.add('active');
        if (helpBox) helpBox.style.display = 'none';
    }
}

// =========================================================================
// Mailbox Connection
// =========================================================================
async function connectMail() {
    const host = document.getElementById('mailHost').value.trim();
    const port = parseInt(document.getElementById('mailPort').value) || 993;
    const email = document.getElementById('mailEmail').value.trim();
    const password = document.getElementById('mailPassword').value;
    const folder = document.getElementById('mailFolder').value.trim() || 'INBOX';
    const interval = parseInt(document.getElementById('mailInterval').value) || 30;
    const feedback = document.getElementById('connectionFeedback');

    if (!host || !email || !password) {
        showToast('Please provide your email and app password.', 'error');
        return;
    }

    const btn = document.getElementById('connectBtn');
    btn.disabled = true;
    btn.textContent = 'Verifying IMAP Credentials…';
    feedback.style.display = 'none';

    try {
        const res = await fetch(`${API}/api/mail/connect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                imap_host: host,
                imap_port: port,
                email: email,
                password: password,
                folder: folder,
                poll_interval: interval,
            })
        });

        const data = await res.json();

        if (res.ok && data.status === 'ok') {
            showToast('Mailbox connected. Protection is now active!', 'success');
            updateScannerBadge(true);
            feedback.className = 'connection-status-block success';
            feedback.innerHTML = `<strong>Connected & Protected:</strong> Monitoring <code>${escapeHtml(email)}</code> (Folder: <code>${escapeHtml(folder)}</code>). Background checks run every ${interval}s.`;
            feedback.style.display = 'block';
            playAlertSound(false);
        } else {
            const errDetail = data.detail || 'Connection failed. Please check credentials.';
            showToast(errDetail, 'error');
            feedback.className = 'connection-status-block error';
            feedback.innerHTML = `<strong>Connection Error:</strong> ${escapeHtml(errDetail)}`;
            feedback.style.display = 'block';
            updateScannerBadge(false);
        }
    } catch (e) {
        showToast('Connection failed: ' + e.message, 'error');
        updateScannerBadge(false);
    } finally {
        btn.textContent = 'Connect & Start Monitoring';
        btn.disabled = false;
    }
}

async function disconnectMail() {
    const btn = document.getElementById('disconnectBtn');
    const feedback = document.getElementById('connectionFeedback');
    btn.disabled = true;

    try {
        const res = await fetch(`${API}/api/mail/disconnect`, { method: 'POST' });
        const data = await res.json();
        showToast(data.message || 'Mailbox disconnected.', 'info');
        updateScannerBadge(false);
        feedback.style.display = 'none';
    } catch (e) {
        showToast('Error stopping scanner: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
    }
}

async function checkScannerStatus() {
    try {
        const res = await fetch(`${API}/api/mail/status`);
        const data = await res.json();
        updateScannerBadge(data.running, data.email);
    } catch (e) {
        updateScannerBadge(false);
    }
}

function updateScannerBadge(running, email = '') {
    const badge = document.getElementById('scannerBadge');
    const text = document.getElementById('scannerBadgeText');
    const connectBtn = document.getElementById('connectBtn');
    const disconnectBtn = document.getElementById('disconnectBtn');
    const defensePill = document.getElementById('defensePill');
    const policyDot = document.getElementById('policyDot');

    if (running) {
        badge.classList.add('active');
        text.textContent = 'Active Protection';
        if (defensePill) {
            defensePill.textContent = 'Online & Protecting';
            defensePill.style.color = 'var(--status-safe)';
        }
        if (policyDot) {
            policyDot.textContent = 'Scanning Live';
        }
        if (connectBtn) connectBtn.disabled = true;
        if (disconnectBtn) disconnectBtn.disabled = false;
    } else {
        badge.classList.remove('active');
        text.textContent = 'Scanner Offline';
        if (defensePill) {
            defensePill.textContent = 'Standby';
            defensePill.style.color = 'var(--muted)';
        }
        if (policyDot) {
            policyDot.textContent = 'Standby';
        }
        if (connectBtn) connectBtn.disabled = false;
        if (disconnectBtn) disconnectBtn.disabled = true;
    }
}

// =========================================================================
// Stats & Chart
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

function initChart() {
    const canvas = document.getElementById('threatChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Clean Delivered', 'Suspicious Flagged', 'Phishing Quarantined'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#5db872', '#d4a017', '#c64545'],
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
// Audit Trail & New Threat Alert Detection
// =========================================================================
async function refreshResults() {
    try {
        const res = await fetch(`${API}/api/results?limit=50`);
        const results = await res.json();

        // Detect newly appeared threats to trigger push notifications
        if (!isInitialLoad && results.length) {
            for (const r of results) {
                if (!knownResultIds.has(r.id)) {
                    knownResultIds.add(r.id);
                    if (r.status === 'Phishing' || r.status === 'Suspicious') {
                        triggerPhishingAlert(r);
                    }
                }
            }
        } else {
            results.forEach(r => knownResultIds.add(r.id));
            isInitialLoad = false;
        }

        allResults = results;
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

        return `<tr onclick="showDetail(${idx})">
            <td>${time}</td>
            <td>${escapeHtml(r.sender || '—')}</td>
            <td>${escapeHtml(r.subject || '(no subject)')}</td>
            <td><span class="status-pill ${statusClass}">${r.status}</span></td>
            <td><span class="score-inline" style="color:${scoreColor}">${r.threat_score.toFixed(1)}</span></td>
            <td>${(r.confidence * 100).toFixed(0)}%</td>
            <td><span class="action-badge">${escapeHtml(r.action)}</span></td>
        </tr>`;
    }).join('');
}

function getScoreColor(score) {
    if (score >= 60) return '#c64545';
    if (score >= 35) return '#d4a017';
    return '#5db872';
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
        <div class="detail-row"><span class="label">Verdict</span><span class="status-pill ${r.status.toLowerCase()}">${r.status}</span></div>
        <div class="detail-row"><span class="label">Threat Score</span><span style="color:${getScoreColor(r.threat_score)}; font-weight:700">${r.threat_score.toFixed(1)} / 100</span></div>
        <div class="detail-row"><span class="label">Confidence</span><span>${(r.confidence * 100).toFixed(0)}%</span></div>
        <div class="detail-row"><span class="label">Action Taken</span><span>${escapeHtml(r.action)}</span></div>
        <div class="detail-row"><span class="label">Timestamp</span><span>${formatTime(r.timestamp)}</span></div>
    `;

    if (r.breakdown) {
        html += `<div style="margin-top:16px;"><span class="breakdown-title">Signal Breakdown</span><div class="breakdown-chips">`;
        for (const [key, val] of Object.entries(r.breakdown)) {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            const color = val > 0 ? 'var(--status-phishing)' : val < 0 ? 'var(--status-safe)' : 'var(--muted)';
            html += `<div class="breakdown-chip"><span class="breakdown-chip-title">${label}</span><span class="breakdown-chip-val" style="color:${color}">${val > 0 ? '+' : ''}${val.toFixed(1)}</span></div>`;
        }
        html += `</div></div>`;
    }

    if (r.evidence && r.evidence.length) {
        html += `<div style="margin-top:16px;"><span class="breakdown-title">Identified Evidence Trail</span><ul class="evidence-list" style="margin-top:8px;">`;
        r.evidence.forEach(ev => {
            const color = ev.contribution > 0 ? 'var(--status-phishing)' : 'var(--status-safe)';
            html += `<li><strong>${escapeHtml(ev.source)}</strong>: ${escapeHtml(ev.detail)} <span style="color:${color}; float:right; font-weight:600;">${ev.contribution > 0 ? '+' : ''}${ev.contribution.toFixed(1)}</span></li>`;
        });
        html += `</ul></div>`;
    }

    if (r.body_preview) {
        html += `<div style="margin-top:16px;"><span class="breakdown-title">Email Body Preview</span><pre class="text-input" style="white-space:pre-wrap; font-family:var(--font-mono); font-size:12px; margin-top:6px; max-height:160px; overflow-y:auto;">${escapeHtml(r.body_preview)}</pre></div>`;
    }

    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('detailModal').classList.add('visible');
}

function closeModal() {
    document.getElementById('detailModal').classList.remove('visible');
}

document.getElementById('detailModal')?.addEventListener('click', (e) => {
    if (e.target === document.getElementById('detailModal')) closeModal();
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
        closeUrgentAlert();
    }
});

// =========================================================================
// Toast Notification
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
