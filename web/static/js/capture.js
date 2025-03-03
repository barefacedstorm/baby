/**
 * JavaScript for the packet capture page
 */

// Global variables
let captureActive = false;
let startTime = 0;
let durationInterval = null;
let refreshInterval = null;
let protocolChart = null;

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize UI elements
    const startBtn = document.getElementById('start-capture');
    const stopBtn = document.getElementById('stop-capture');
    const refreshBtn = document.getElementById('refresh-interfaces');

    // Setup button event listeners
    if (startBtn) startBtn.addEventListener('click', startCapture);
    if (stopBtn) stopBtn.addEventListener('click', stopCapture);
    if (refreshBtn) refreshBtn.addEventListener('click', () => refreshInterfaces('interface'));

    // Initialize chart if element exists
    const chartCanvas = document.getElementById('protocol-chart');
    if (chartCanvas) {
        protocolChart = new Chart(chartCanvas, {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#7c4dff',
                        '#4dabff',
                        '#00c853',
                        '#ffab00',
                        '#ff5252',
                        '#aa00ff',
                        '#18ffff',
                        '#ffff00'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#ffffff'
                        }
                    }
                }
            }
        });
    }
});

// Start packet capture
function startCapture() {
    const interfaceSelect = document.getElementById('interface');
    const countInput = document.getElementById('count');
    const continuousCheckbox = document.getElementById('continuous');
    const outputDirInput = document.getElementById('output-dir');
    const startBtn = document.getElementById('start-capture');
    const stopBtn = document.getElementById('stop-capture');

    // Validate input
    if (!interfaceSelect.value) {
        showNotification('Please select a network interface', 'error');
        return;
    }

    // Prepare request data
    const requestData = {
        interface: interfaceSelect.value,
        count: parseInt(countInput.value) || 100,
        continuous: continuousCheckbox.checked,
        output_dir: outputDirInput.value || null
    };

    // Send API request
    fetch('/api/start_capture', {
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
            captureActive = true;
            startTime = Date.now();

            // Update status display
            document.getElementById('capture-status').textContent = 'Running';

            // Disable start button, enable stop button
            if (startBtn) startBtn.disabled = true;
            if (stopBtn) stopBtn.disabled = false;

            // Start updating duration
            durationInterval = setInterval(updateDuration, 1000);

            // Start refreshing capture status
            refreshInterval = setInterval(refreshCaptureStatus, 2000);

            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error starting capture:', error);
        showNotification('Failed to start capture', 'error');
    });
}

// Stop packet capture
function stopCapture() {
    fetch('/api/stop_capture', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Reset UI
            captureActive = false;

            // Update status display
            document.getElementById('capture-status').textContent = 'Stopped';

            // Re-enable start button, disable stop button
            document.getElementById('start-capture').disabled = false;
            document.getElementById('stop-capture').disabled = true;

            // Stop intervals
            clearInterval(durationInterval);
            clearInterval(refreshInterval);

            // Final refresh of capture status
            refreshCaptureStatus();

            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error stopping capture:', error);
        showNotification('Failed to stop capture', 'error');
    });
}

// Update capture duration display
function updateDuration() {
    if (!captureActive) return;

    const durationElement = document.getElementById('capture-duration');
    const elapsedSeconds = Math.floor((Date.now() - startTime) / 1000);

    if (durationElement) {
        durationElement.textContent = formatDuration(elapsedSeconds);
    }
}

// Refresh capture status and results
function refreshCaptureStatus() {
    fetch('/api/capture_status')
        .then(response => response.json())
        .then(data => {
            // Update packet count
            document.getElementById('packet-count').textContent = data.packets || 0;

            // Update protocol distribution if there are results
            if (data.results && Object.keys(data.results).length > 0) {
                updateProtocolChart(data.results);
                updateProtocolTable(data.results);
            }

            // If capture is no longer active but our UI thinks it is, reset the UI
            if (!data.active && captureActive) {
                captureActive = false;
                document.getElementById('capture-status').textContent = 'Stopped';
                document.getElementById('start-capture').disabled = false;
                document.getElementById('stop-capture').disabled = true;
                clearInterval(durationInterval);
                clearInterval(refreshInterval);
            }
        })
        .catch(error => {
            console.error('Error refreshing capture status:', error);
        });
}

// Update protocol distribution chart
function updateProtocolChart(results) {
    if (!protocolChart) return;

    const protocols = Object.keys(results);
    const counts = protocols.map(p => results[p]);

    protocolChart.data.labels = protocols;
    protocolChart.data.datasets[0].data = counts;
    protocolChart.update();
}

// Update protocol table
function updateProtocolTable(results) {
    const tableBody = document.getElementById('protocol-table-body');
    if (!tableBody) return;

    // Clear existing rows
    tableBody.innerHTML = '';

    // Calculate total packets
    const totalPackets = Object.values(results).reduce((sum, count) => sum + count, 0);

    // Add new rows
    Object.entries(results).forEach(([protocol, count]) => {
        const percentage = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(2) : '0.00';

        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${protocol}</td>
            <td>${count}</td>
            <td>${percentage}%</td>
        `;

        tableBody.appendChild(row);
    });
}
