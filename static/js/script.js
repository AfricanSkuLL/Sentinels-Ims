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
        updateSecurityUI(data.user);
        updateLogTable(data.logs);
    } catch (error) {
        console.error('Inquisitor Error:', error);
    }
}

function updateSecurityUI(user) {
    const strikeDisplay = document.getElementById('strike-display');
    const statusDisplay = document.getElementById('status-display');
    const postureCard = document.getElementById('posture-card');
    const banner = document.getElementById('lockdown-banner');

    strikeDisplay.innerText = user.strike_count;

    if (user.is_locked) {
        statusDisplay.innerText = "LOCKDOWN ACTIVE";
        postureCard.classList.add('locked-state');
        banner.classList.remove('hidden');
    } else {
        statusDisplay.innerText = user.strike_count > 0 ? "WARNING" : "STABLE";
        postureCard.classList.remove('locked-state');
        banner.classList.add('hidden');
    }
}

function updateLogTable(logs) {
    const tbody = document.getElementById('log-body');
    tbody.innerHTML = ''; // Clear existing rows

    logs.forEach(log => {
        const tr = document.createElement('tr');
        if (log.alert_level > 0) tr.classList.add('alert-row');

        tr.innerHTML = `
            <td>${log.timestamp}</td>
            <td>${log.device_name}</td>
            <td>${log.event_details}</td>
            <td>${log.alert_level}</td>
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
                refreshDashboard();
            }
        } catch (error) {
            alert("Reset failed. Check SOC connection.");
        }
    }
}

// Initial update and periodic polling (Standard Web API)
refreshDashboard();
setInterval(refreshDashboard, 5000);
