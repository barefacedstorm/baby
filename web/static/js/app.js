/**
 * Main application JavaScript for Baby DPI
 */

// Show notification message
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;

    // Add to DOM
    document.body.appendChild(notification);

    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// Format timestamp to local time
function formatTimestamp(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString();
}

// Format duration (seconds to HH:MM:SS)
function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    return [
        hours.toString().padStart(2, '0'),
        minutes.toString().padStart(2, '0'),
        secs.toString().padStart(2, '0')
    ].join(':');
}

// Refresh interfaces list
function refreshInterfaces(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return;

    fetch('/api/interfaces')
        .then(response => response.json())
        .then(data => {
            // Clear existing options
            while (select.options.length > 0) {
                select.remove(0);
            }

            // Add empty option
            const emptyOption = document.createElement('option');
            emptyOption.value = '';
            emptyOption.textContent = 'Select an interface';
            select.appendChild(emptyOption);

            // Add interface options
            data.interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                select.appendChild(option);
            });
        })
        .catch(error => {
            console.error('Error fetching interfaces:', error);
            showNotification('Failed to fetch network interfaces', 'error');
        });
}
