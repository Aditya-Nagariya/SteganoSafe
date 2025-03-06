document.addEventListener('DOMContentLoaded', function() {
    // Only initialize charts if their containers exist
    function initCharts() {
        // Check if containers exist before initializing charts
        const userStatsContainer = document.getElementById('userStatsChart');
        const encryptionStatsContainer = document.getElementById('encryptionStatsChart');
        
        // Only initialize if container exists
        if (userStatsContainer) {
            // User stats chart initialization
            const userCtx = userStatsContainer.getContext('2d');
            new Chart(userCtx, {
                // ...existing chart configuration...
            });
        }
        
        // Only initialize if container exists
        if (encryptionStatsContainer) {
            // Encryption stats chart initialization  
            const encryptionCtx = encryptionStatsContainer.getContext('2d');
            new Chart(encryptionCtx, {
                // ...existing chart configuration...
            });
        }
        
        // IMPORTANT: Remove any extra chart initializations or empty chart containers
        // Look for any chart containers that might be empty or duplicated
        document.querySelectorAll('canvas').forEach(canvas => {
            // If canvas has no height or width, or is empty, hide it
            if (canvas.width === 0 || canvas.height === 0 || !canvas.id) {
                canvas.style.display = 'none';
            }
        });
    }
    
    // Only call initCharts if we're on the admin dashboard page
    if (window.location.pathname === '/admin/' || window.location.pathname === '/admin') {
        initCharts();
    }
});
