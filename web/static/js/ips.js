/**
 * JavaScript for the IPS engine page
 */

// Global variables
let ipsActive = false;
let refreshInterval = null;

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize UI elements
    const startBtn = document.getElementById('start-ips');
    const stopBtn = document.getElementById('stop-ips');
    const refreshBtn = document.getElementById('refresh-ips-interfaces');

    // Setup button event listeners
    if (startBtn) startBtn.addEventListener('click', startIPS);
    if (stopBtn) stopBtn.addEventListener('click', stopIPS);
    if (refreshBtn) refreshBtn.addEventListener('click', () => refreshInterfaces('ips-interface'));
});

// Start IPS engine
function startIPS() {
    const interfaceSelect = document.getElementById('ips-interface');
    const continuousCheckbox = document.getElementById('ips-continuous');
    const outputDirInput = document.getElementById('ips-output-dir');
    const startBtn = document.getElementById('start-ips');
    const stopBtn = document.getElementById('stop-ips');

    // Validate input
    if (!interfaceSelect.value) {
        showNotification('Please select a network interface', 'error');
        return;
    }

    // Prepare request data
    const requestData = {
        interface: interfaceSelect.value,
        continuous: continuousCheckbox.checked,
        output_dir: outputDirInput.value || null
    };

    // Send API request
    fetch('/api/start_ips', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update UI
            ipsActive = true;

            // Disable start button, enable stop button
            if (startBtn) startBtn.disabled = true;
            if (stopBtn) stopBtn.disabled = false;

            // Start refreshing alerts
            refreshInterval = setInterval(refreshAlerts, 2000);

            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error starting IPS:', error);
        showNotification('Failed to start IPS engine', 'error');
    });
}

// Stop IPS engine
function stopIPS() {
    fetch('/api/stop_ips', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Reset UI
            ipsActive = false;

            // Re-enable start button, disable stop button
            document.getElementById('start-ips').disabled = false;
            document.getElementById('stop-ips').disabled = true;

            // Stop interval
            clearInterval(refreshInterval);

            // Final refresh of alerts
            refreshAlerts();

            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error stopping IPS:', error);
        showNotification('Failed to stop IPS engine', 'error');
    });
}

// Refresh alert data
function refreshAlerts() {
    fetch('/api/ips_alerts')
        .then(response => response.json())
        .then(data => {
            // If IPS is no longer active but our UI thinks it is, reset the UI
            if (!data.active && ipsActive) {
                ipsActive = false;
                document.getElementById('start-ips').disabled = false;
                document.getElementById('stop-ips').disabled = true;
                clearInterval(refreshInterval);
            }

            // Update alerts if there are any
            if (data.alerts && data.alerts.length > 0) {
                updateAlertStats(data.alerts);
                updateAlertsTable(data.alerts);
            }
        })
        .catch(error => {
            console.error('Error refreshing alerts:', error);
        });
}

// Update alert statistics
function updateAlertStats(alerts) {
    // Count total alerts
    document.getElementById('total-alerts').textContent = alerts.length;

    // Count by severity
    const highSeverity = alerts.filter(alert => alert.severity >= 5).length;
    const mediumSeverity = alerts.filter(alert => alert.severity >= 3 && alert.severity < 5).length;
    const lowSeverity = alerts.filter(alert => alert.severity < 3).length;

    document.getElementById('high-severity').textContent = highSeverity;
    document.getElementById('medium-severity').textContent = mediumSeverity;
    document.getElementById('low-severity').textContent = lowSeverity;
}

// Update alerts table
function updateAlertsTable(alerts) {
    const tableBody = document.getElementById('alerts-table-body');
    if (!tableBody) return;

    // Clear existing rows
    tableBody.innerHTML = '';

    // Sort alerts by timestamp (newest first)
    const sortedAlerts = [...alerts].sort((a, b) => b.timestamp - a.timestamp);

    // Add new rows
    sortedAlerts.forEach(alert => {
        const row = document.createElement('tr');

        // Determine severity class
        let severityClass = 'level-1';
        if (alert.severity >= 5) {
            severityClass = 'level-5';
        } else if (alert.severity >= 3) {
            severityClass = 'level-3';
        }

        row.innerHTML = `
            <td>${formatTimestamp(alert.timestamp)}</td>
            <td>${alert.rule}</td>
            <td><span class="severity-badge ${severityClass}">${alert.severity}</span></td>
            <td>${alert.src_ip}</td>
            <td>${alert.dst_ip}</td>
            <td>${alert.description}</td>
        `;

        tableBody.appendChild(row);
    });
}
