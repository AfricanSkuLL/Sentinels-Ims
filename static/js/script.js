/* Sentinels-IMS Frontend Controller */

/**
 * Fetches current system state from the Flask /status endpoint
 * and updates the DOM.
 */
async function refreshDashboard() {
    try {
        const response = await fetch('/status');
        if (!response.ok) throw new Error('Network response error');

        const data = await response.json();
        
        // Handle array or object structure safely
        const user = Array.isArray(data.user) ? data.user[0] : data.user;
        const logs = data.logs || [];

        if (user) {
            updateSecurityUI(user);
        }
        updateLogTable(logs);
    } catch (error) {
        console.error('Inquisitor Error:', error);
    }
}

function updateSecurityUI(user) {
    const strikeDisplay = document.getElementById('strike-display');
    const statusDisplay = document.getElementById('status-display');
    const postureCard = document.getElementById('posture-card');
    const banner = document.getElementById('lockdown-banner');

    // Parse values to integers to handle stringified JSON numbers like "0"
    const strikeCount = parseInt(user?.strike_count ?? 0, 10);
    const isLockedInt = parseInt(user?.is_locked ?? 0, 10);

    if (strikeDisplay) strikeDisplay.innerText = strikeCount;

    // Evaluates TRUE only if is_locked parses to 1
    if (isLockedInt === 1) {
        if (statusDisplay) statusDisplay.innerText = "LOCKDOWN ACTIVE";
        if (postureCard) postureCard.classList.add('locked-state');
        if (banner) banner.classList.remove('hidden');
    } else {
        if (statusDisplay) statusDisplay.innerText = strikeCount > 0 ? "WARNING" : "STABLE";
        if (postureCard) postureCard.classList.remove('locked-state');
        if (banner) banner.classList.add('hidden');
    }
}

function updateLogTable(logs) {
    const tbody = document.getElementById('log-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!Array.isArray(logs)) return;

    logs.forEach(log => {
        const tr = document.createElement('tr');
        if (log.alert_level > 0) tr.classList.add('alert-row');

        tr.innerHTML = `
            <td>${log.timestamp || ''}</td>
            <td>${log.device_name || ''}</td>
            <td>${log.event_details || ''}</td>
            <td>${log.alert_level || 0}</td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Sends a POST request to /reset to clear strikes.
 */
async function resetStrikes() {
    if (confirm("PROCEED WITH ADMINISTRATIVE RESET?")) {
        try {
            const response = await fetch('/reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (response.ok) {
                alert("Security protocols restored.");
                await refreshDashboard();
            }
        } catch (error) {
            alert("Reset failed. Check SOC connection.");
        }
    }
}

// Initial load and periodic polling every 5 seconds
refreshDashboard();
setInterval(refreshDashboard, 5000);