/**
 * Minimal Analytics Core - Ultra simplified version with no dependencies
 */

// Sample data that can't fail
const MINIMAL_DATA = {
    success: true,
    summary: {
        total_users: 42, 
        encryptions: 150,
        decryptions: 85,
        active_users: 18
    },
    top_users: [
        { username: 'admin', id: 1, activity_count: 45, encryptions: 30, decryptions: 15, last_active: 'Just now' }
    ]
};

// Format a number with commas
function formatNumber(num) {
    if (!num && num !== 0) return "-";
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Populate stats on the page
function updateStats() {
    try {
        // Basic stats
        const elements = {
            'stat-total-users': MINIMAL_DATA.summary.total_users,
            'stat-total-encryptions': MINIMAL_DATA.summary.encryptions,
            'stat-total-decryptions': MINIMAL_DATA.summary.decryptions,
            'stat-active-users': MINIMAL_DATA.summary.active_users
        };
        
        // Update each element
        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = formatNumber(value);
            }
        }
        
        // Show the content, hide loading
        const loading = document.getElementById('loading');
        if (loading) loading.style.display = 'none';
        
        const content = document.getElementById('analytics-content');
        if (content) content.style.display = 'block';
        
        console.log('Stats updated with minimal data');
    } catch (e) {
        console.error('Error in minimal analytics:', e);
        alert('Error loading analytics. Please check the console for details.');
    }
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', function() {
    console.log('Minimal analytics loaded');
    updateStats();
});

// Export for global access
window.MinimalAnalytics = {
    updateStats: updateStats,
    data: MINIMAL_DATA
};
