/**
 * UISP Auto-Adopter — Dashboard JavaScript
 * Real-time scan management and device monitoring
 */

// ================================================================
// STATE
// ================================================================
const state = {
    currentTab: 'overview',
    isScanning: false,
    pollInterval: null,
    devices: [],
    stats: {},
    subnets: [],
    toastTimeout: null
};

// ================================================================
// INITIALIZATION
// ================================================================
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    loadDashboard();
    // Auto-refresh every 30 seconds when not scanning
    setInterval(() => {
        if (!state.isScanning) loadStats();
    }, 30000);
});

function initTabs() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            switchTab(target);
        });
    });
}

function switchTab(tabName) {
    state.currentTab = tabName;

    // Update tab buttons
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.nav-tab[data-tab="${tabName}"]`)?.classList.add('active');

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${tabName}`)?.classList.add('active');

    // Load data for the tab
    switch (tabName) {
        case 'overview': loadStats(); break;
        case 'scan': loadScanStatus(); break;
        case 'devices': loadDevices(); break;
        case 'subnets': loadSubnets(); break;
        case 'config': loadConfig(); break;
        case 'logs': loadLogs(); break;
    }
}

async function loadDashboard() {
    await Promise.all([loadStats(), loadScanStatus()]);
}

// ================================================================
// API CALLS
// ================================================================

async function apiGet(url) {
    try {
        const res = await fetch(url);
        return await res.json();
    } catch (err) {
        console.error(`API Error (${url}):`, err);
        return null;
    }
}

async function apiPost(url, data = {}) {
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await res.json();
    } catch (err) {
        console.error(`API Error (${url}):`, err);
        return null;
    }
}

async function apiDelete(url, data = {}) {
    try {
        const res = await fetch(url, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await res.json();
    } catch (err) {
        console.error(`API Error (${url}):`, err);
        return null;
    }
}

// ================================================================
// STATS / OVERVIEW
// ================================================================

async function loadStats() {
    const stats = await apiGet('/api/stats');
    if (!stats) return;

    state.stats = stats;

    // Update stat cards
    animateNumber('stat-total-devices', stats.total_adopted_all_time || 0);
    animateNumber('stat-networks', stats.network_count || 0);
    animateNumber('stat-last-adopted', stats.adopted || 0);
    animateNumber('stat-last-failed', stats.failed || 0);

    // Update configuration status
    const statusBadge = document.getElementById('config-status');
    if (statusBadge) {
        if (stats.is_configured) {
            statusBadge.className = 'status-badge configured';
            statusBadge.innerHTML = '<span class="status-dot green"></span> Yapılandırıldı';
        } else {
            statusBadge.className = 'status-badge not-configured';
            statusBadge.innerHTML = '<span class="status-dot red"></span> Yapılandırma Gerekli';
        }
    }

    // Update last scan info
    const lastScanEl = document.getElementById('last-scan-info');
    if (lastScanEl && stats.scan_date) {
        const d = new Date(stats.scan_date);
        const elapsed = stats.duration_seconds || 0;
        lastScanEl.innerHTML = `
            <div class="config-item">
                <span class="config-label">Son Tarama</span>
                <span class="config-value">${d.toLocaleString('tr-TR')}</span>
            </div>
            <div class="config-item">
                <span class="config-label">Süre</span>
                <span class="config-value">${elapsed}s</span>
            </div>
            <div class="config-item">
                <span class="config-label">UBIOS Router</span>
                <span class="config-value">${stats.ubios_adopted || 0} cihaz</span>
            </div>
            <div class="config-item">
                <span class="config-label">AirOS Anten</span>
                <span class="config-value">${stats.airos_adopted || 0} cihaz</span>
            </div>
        `;
    }
}

function animateNumber(elementId, targetValue) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const current = parseInt(el.textContent) || 0;
    if (current === targetValue) return;

    const duration = 600;
    const start = performance.now();

    function update(timestamp) {
        const progress = Math.min((timestamp - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
        const value = Math.round(current + (targetValue - current) * eased);
        el.textContent = value;
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

// ================================================================
// SCAN CONTROL
// ================================================================

async function startScan() {
    const dryRun = document.getElementById('dry-run-checkbox')?.checked || false;
    const threadsInput = document.getElementById('threads-input');
    const threads = threadsInput ? parseInt(threadsInput.value) || 10 : 10;

    const result = await apiPost('/api/scan/start', { dry_run: dryRun, threads: threads });

    if (result?.error) {
        showToast(result.error, 'error');
        return;
    }

    state.isScanning = true;
    showToast(dryRun ? '🧪 Deneme taraması başlatıldı...' : '🚀 Tarama başlatıldı!', 'info');

    updateScanUI(true);
    startPolling();
}

async function stopScan() {
    await apiPost('/api/scan/stop');
    showToast('🛑 Durdurma isteği gönderildi...', 'warning');
}

function startPolling() {
    if (state.pollInterval) clearInterval(state.pollInterval);
    state.pollInterval = setInterval(pollScanStatus, 1000);
}

function stopPolling() {
    if (state.pollInterval) {
        clearInterval(state.pollInterval);
        state.pollInterval = null;
    }
}

async function pollScanStatus() {
    const status = await apiGet('/api/scan/status');
    if (!status) return;

    updateScanProgress(status);

    if (!status.is_running && state.isScanning) {
        state.isScanning = false;
        stopPolling();
        updateScanUI(false);
        showToast('✅ Tarama tamamlandı!', 'success');
        loadStats(); // Refresh stats
    }
}

async function loadScanStatus() {
    const status = await apiGet('/api/scan/status');
    if (!status) return;

    if (status.is_running) {
        state.isScanning = true;
        updateScanUI(true);
        startPolling();
    }

    updateScanProgress(status);
}

function updateScanProgress(status) {
    // Progress bar
    const progressBar = document.getElementById('scan-progress-bar');
    const progressPercent = document.getElementById('scan-progress-percent');
    const progressElapsed = document.getElementById('scan-progress-elapsed');
    const progressAdopted = document.getElementById('scan-progress-adopted');

    if (progressBar) {
        progressBar.style.width = `${status.progress || 0}%`;
        progressBar.className = `progress-bar${status.is_running ? ' active' : ''}`;
    }
    if (progressPercent) progressPercent.textContent = `${status.progress || 0}%`;
    if (progressElapsed) progressElapsed.textContent = `${formatDuration(status.elapsed_seconds || 0)}`;
    if (progressAdopted) {
        progressAdopted.textContent = `✅ ${status.adopted || 0} başarılı  ❌ ${status.failed || 0} başarısız`;
    }

    // Running indicator
    const indicator = document.getElementById('scan-running-indicator');
    if (indicator) {
        indicator.classList.toggle('hidden', !status.is_running);
    }

    // Live log
    updateLiveLog(status.live_log || []);
}

function updateLiveLog(logs) {
    const logContainer = document.getElementById('live-log');
    if (!logContainer) return;

    if (logs.length === 0) {
        logContainer.innerHTML = '<div class="empty-state"><div class="empty-icon">📋</div><div class="empty-desc">Henüz log yok...</div></div>';
        return;
    }

    const html = logs.map(entry => `
        <div class="log-entry ${entry.level}">
            <span class="log-time">${entry.time}</span>
            <span class="log-message">${escapeHtml(entry.message)}</span>
        </div>
    `).join('');

    logContainer.innerHTML = html;
    logContainer.scrollTop = logContainer.scrollHeight;
}

function updateScanUI(isRunning) {
    const startBtn = document.getElementById('btn-start-scan');
    const stopBtn = document.getElementById('btn-stop-scan');

    if (startBtn) startBtn.disabled = isRunning;
    if (stopBtn) stopBtn.disabled = !isRunning;
}

// ================================================================
// DEVICES
// ================================================================

async function loadDevices() {
    const data = await apiGet('/api/devices');
    if (!data) return;

    state.devices = data.devices || [];

    const countEl = document.getElementById('device-count');
    if (countEl) countEl.textContent = `${data.total} cihaz`;

    renderDeviceTable(state.devices);
    populateSubnetFilter(state.devices);
}

function renderDeviceTable(devices) {
    const tbody = document.getElementById('device-table-body');
    if (!tbody) return;

    if (devices.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center" style="padding:40px; color: var(--text-muted);">
                    Henüz cihaz yok
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = devices.map((device, idx) => `
        <tr>
            <td style="color: var(--text-muted); font-size: 0.8rem;">${idx + 1}</td>
            <td class="ip-cell">${device.ip}</td>
            <td class="subnet-cell">${device.subnet}</td>
            <td><span class="status-tag adopted">✅ Bağlı</span></td>
        </tr>
    `).join('');
}

function populateSubnetFilter(devices) {
    const select = document.getElementById('subnet-filter');
    if (!select) return;

    const subnets = [...new Set(devices.map(d => d.subnet))].sort();
    const currentValue = select.value;

    select.innerHTML = '<option value="">Tüm Alt Ağlar</option>' +
        subnets.map(s => `<option value="${s}">${s}</option>`).join('');

    select.value = currentValue;
}

function filterDevices() {
    const searchTerm = document.getElementById('device-search')?.value.toLowerCase() || '';
    const subnetFilter = document.getElementById('subnet-filter')?.value || '';

    let filtered = state.devices;

    if (searchTerm) {
        filtered = filtered.filter(d => d.ip.includes(searchTerm));
    }
    if (subnetFilter) {
        filtered = filtered.filter(d => d.subnet === subnetFilter);
    }

    renderDeviceTable(filtered);

    const countEl = document.getElementById('device-count');
    if (countEl) {
        countEl.textContent = filtered.length === state.devices.length
            ? `${state.devices.length} cihaz`
            : `${filtered.length} / ${state.devices.length} cihaz`;
    }
}

// ================================================================
// SUBNETS
// ================================================================

async function loadSubnets() {
    const data = await apiGet('/api/subnet-stats');
    if (!data) return;

    state.subnets = data.subnets || [];

    const container = document.getElementById('subnet-grid');
    if (!container) return;

    if (state.subnets.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">🌐</div><div class="empty-title">Alt ağ verisi yok</div></div>';
        return;
    }

    const totalDevices = state.subnets.reduce((sum, s) => sum + s.count, 0);

    container.innerHTML = state.subnets.map(subnet => {
        const percent = ((subnet.count / totalDevices) * 100).toFixed(1);
        return `
        <div class="subnet-card">
            <div>
                <div class="subnet-name">${subnet.subnet}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">${percent}%</div>
            </div>
            <div class="subnet-count-badge">${subnet.count}</div>
        </div>`;
    }).join('');
}

async function loadConfig() {
    const config = await apiGet('/api/config');
    if (!config) return;

    state.config = config;

    // Populate UISP connection string
    const uispInput = document.getElementById('uisp-string-input');
    if (uispInput) uispInput.value = config.uisp_connection_string || '';

    // Populate network ranges
    renderNetworkList(config.network_ranges || []);

    // Populate credentials
    renderCredentialList(config.credentials || []);

    // Populate settings
    const s = config.settings || {};
    setInputValue('setting-max-threads', s.max_threads || 10);
    setInputValue('setting-ssh-timeout', s.ssh_timeout || 5);
    setInputValue('setting-port-timeout', s.port_scan_timeout || 0.3);
    setInputValue('setting-dashboard-port', s.dashboard_port || 5050);
}

function setInputValue(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value;
}

// ── Network Ranges ──

function renderNetworkList(networks) {
    const container = document.getElementById('network-list-container');
    const badge = document.getElementById('network-count-badge');
    if (badge) badge.textContent = `${networks.length} ağ`;
    if (!container) return;

    if (networks.length === 0) {
        container.innerHTML = '<div class="empty-state" style="padding: 20px;"><div class="empty-desc">Henüz ağ aralığı eklenmemiş</div></div>';
        return;
    }

    container.innerHTML = networks.map((net, idx) => `
        <div class="subnet-card" style="margin-bottom: 8px;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: var(--text-muted); font-size: 0.8rem; width: 24px;">${idx + 1}.</span>
                <span class="subnet-name">${net}</span>
            </div>
            <button class="btn btn-danger btn-sm" onclick="removeNetwork('${net}')">
                🗑️ Sil
            </button>
        </div>
    `).join('');
}

async function addNetwork() {
    const input = document.getElementById('new-network-input');
    const network = input?.value.trim();
    if (!network) {
        showToast('Lütfen ağ aralığı girin (örn: 10.0.0.0/24)', 'error');
        return;
    }

    const result = await apiPost('/api/config/networks', { network });

    if (result?.error) {
        showToast(`❌ ${result.error}`, 'error');
        return;
    }

    showToast(`✅ ${result.network} eklendi!`, 'success');
    if (input) input.value = '';
    loadConfig();
    loadStats(); // Refresh network count
}

async function removeNetwork(network) {
    if (!confirm(`"${network}" ağını silmek istediğinizden emin misiniz?`)) return;

    const result = await apiDelete('/api/config/networks', { network });

    if (result?.error) {
        showToast(`❌ ${result.error}`, 'error');
        return;
    }

    showToast(`🗑️ ${network} silindi.`, 'warning');
    loadConfig();
    loadStats();
}

// ── Credentials ──

function renderCredentialList(credentials) {
    const container = document.getElementById('credential-list-container');
    const badge = document.getElementById('cred-count-badge');
    if (badge) badge.textContent = `${credentials.length} kimlik`;
    if (!container) return;

    if (credentials.length === 0) {
        container.innerHTML = '<div class="empty-state" style="padding: 20px;"><div class="empty-desc">Henüz kimlik bilgisi eklenmemiş</div></div>';
        return;
    }

    container.innerHTML = credentials.map((cred, idx) => {
        const maskedPass = '•'.repeat(Math.min(cred.password.length, 12));
        return `
        <div class="subnet-card" style="margin-bottom: 8px;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <span style="color: var(--text-muted); font-size: 0.8rem; width: 24px;">${idx + 1}.</span>
                <span style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 500;">${escapeHtml(cred.username)}</span>
                <span style="font-family: var(--font-mono); color: var(--text-muted); font-size: 0.8rem;" 
                      id="cred-pass-${idx}" 
                      onclick="togglePassword(${idx}, '${escapeHtml(cred.password)}')"
                      title="Görmek için tıklayın"
                      style="cursor: pointer;">${maskedPass}</span>
            </div>
            <button class="btn btn-danger btn-sm" onclick="removeCredential(${idx}, '${escapeHtml(cred.username)}')">
                🗑️ Sil
            </button>
        </div>
    `}).join('');
}

function togglePassword(idx, password) {
    const el = document.getElementById(`cred-pass-${idx}`);
    if (!el) return;
    const masked = '•'.repeat(Math.min(password.length, 12));
    if (el.textContent === masked) {
        el.textContent = password;
        el.style.color = 'var(--accent-orange)';
    } else {
        el.textContent = masked;
        el.style.color = 'var(--text-muted)';
    }
}

async function addCredential() {
    const usernameInput = document.getElementById('new-cred-username');
    const passwordInput = document.getElementById('new-cred-password');
    const username = usernameInput?.value.trim();
    const password = passwordInput?.value.trim();

    if (!username || !password) {
        showToast('Kullanıcı adı ve şifre gerekli', 'error');
        return;
    }

    const result = await apiPost('/api/config/credentials', { username, password });

    if (result?.error) {
        showToast(`❌ ${result.error}`, 'error');
        return;
    }

    showToast(`✅ ${username} eklendi!`, 'success');
    if (usernameInput) usernameInput.value = '';
    if (passwordInput) passwordInput.value = '';
    loadConfig();
}

async function removeCredential(index, username) {
    if (!confirm(`"${username}" kimliğini silmek istediğinizden emin misiniz?`)) return;

    const result = await apiDelete('/api/config/credentials', { index });

    if (result?.error) {
        showToast(`❌ ${result.error}`, 'error');
        return;
    }

    showToast(`🗑️ ${username} silindi.`, 'warning');
    loadConfig();
}

// ── UISP Connection String ──

async function saveUispString() {
    const input = document.getElementById('uisp-string-input');
    const value = input?.value.trim();

    if (!value) {
        showToast('UISP bağlantı dizesi boş olamaz', 'error');
        return;
    }

    const result = await apiPost('/api/config/uisp', { uisp_connection_string: value });

    if (result?.error) {
        showToast(`❌ ${result.error}`, 'error');
        return;
    }

    showToast('✅ UISP bağlantı dizesi güncellendi!', 'success');
    loadStats();
}

// ── Settings ──

async function saveSettings() {
    const settings = {
        max_threads: parseInt(document.getElementById('setting-max-threads')?.value) || 10,
        ssh_timeout: parseFloat(document.getElementById('setting-ssh-timeout')?.value) || 5,
        port_scan_timeout: parseFloat(document.getElementById('setting-port-timeout')?.value) || 0.3,
        dashboard_port: parseInt(document.getElementById('setting-dashboard-port')?.value) || 5050
    };

    const result = await apiPost('/api/config/settings', settings);

    if (result?.error) {
        showToast(`❌ ${result.error}`, 'error');
        return;
    }

    showToast('✅ Ayarlar kaydedildi!', 'success');
}

// ================================================================
// LOGS
// ================================================================

async function loadLogs() {
    const data = await apiGet('/api/logs');
    if (!data) return;

    const container = document.getElementById('file-log');
    if (!container) return;

    if (!data.logs || data.logs.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">📋</div><div class="empty-desc">Log dosyası boş</div></div>';
        return;
    }

    container.innerHTML = data.logs.map(line => {
        let level = 'INFO';
        if (line.includes('WARNING') || line.includes('⛔')) level = 'WARNING';
        if (line.includes('ERROR') || line.includes('❌')) level = 'ERROR';
        return `<div class="log-entry ${level}"><span class="log-message">${escapeHtml(line)}</span></div>`;
    }).join('');

    container.scrollTop = container.scrollHeight;
}

// ================================================================
// SINGLE DEVICE ADOPT
// ================================================================

async function adoptSingleDevice() {
    const ipInput = document.getElementById('single-ip-input');
    const ip = ipInput?.value.trim();

    if (!ip) {
        showToast('Lütfen bir IP adresi girin', 'error');
        return;
    }

    // Basic IP validation
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        showToast('Geçersiz IP adresi formatı', 'error');
        return;
    }

    const dryRun = document.getElementById('single-dry-run')?.checked || false;

    showToast(`🔎 ${ip} kontrol ediliyor...`, 'info');

    const result = await apiPost('/api/scan/adopt-single', { ip: ip, dry_run: dryRun });

    if (!result) {
        showToast('API hatası!', 'error');
        return;
    }

    const resultContainer = document.getElementById('single-adopt-result');
    if (resultContainer) {
        const statusClass = result.status === 'adopted' ? 'adopted' : 'failed';
        const statusText = result.status === 'adopted' ? '✅ Başarılı' : '❌ Başarısız';
        resultContainer.innerHTML = `
            <div class="result-card">
                <span class="result-ip">${result.ip}</span>
                <span class="result-type">${result.device_type || 'Bilinmiyor'}</span>
                <span class="status-tag ${statusClass}">${statusText}</span>
                ${result.error ? `<span style="color: var(--accent-red); font-size: 0.8rem;">${result.error}</span>` : ''}
            </div>
        `;
        resultContainer.classList.remove('hidden');
    }

    if (result.status === 'adopted') {
        showToast(`✅ ${ip} başarıyla bağlandı!`, 'success');
        if (ipInput) ipInput.value = '';
    } else {
        showToast(`❌ ${ip}: ${result.error || 'Bağlantı başarısız'}`, 'error');
    }
}

// ================================================================
// UTILITIES
// ================================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDuration(seconds) {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    const min = Math.floor(seconds / 60);
    const sec = Math.round(seconds % 60);
    return `${min}m ${sec}s`;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'toastOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Debounce helper
function debounce(fn, delay) {
    let timer;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}

// Debounce device filter
const debouncedFilter = debounce(filterDevices, 200);
