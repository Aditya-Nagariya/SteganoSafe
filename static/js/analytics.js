/**
 * Analytics visualization utilities for SteganoSafe
 */

// Global chart references
let usageChart = null;
let methodsChart = null;

/**
 * Initialize analytics charts and displays
 */
function initAnalytics() {
    // Check if Chart.js is loaded
    if (typeof Chart === 'undefined') {
        console.error('Chart.js not loaded. Please include Chart.js library.');
        showError('Chart.js library not loaded. Please check your network connection.');
        return;
    }

    console.log('Initializing analytics charts...');
    
    // Set up charts if the containers exist
    if (document.getElementById('usageChart')) {
        console.log('Creating usage chart');
        createUsageChart();
    } else {
        console.warn('Usage chart container not found');
    }
    
    if (document.getElementById('methodsChart')) {
        console.log('Creating methods chart');
        createMethodsChart();
    } else {
        console.warn('Methods chart container not found');
    }
    
    // Load trend data
    loadTrends();
}

/**
 * Create usage trend chart
 */
function createUsageChart() {
    const ctx = document.getElementById('usageChart').getContext('2d');
    usageChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['7 Days Ago', '6 Days Ago', '5 Days Ago', '4 Days Ago', '3 Days Ago', '2 Days Ago', 'Yesterday', 'Today'],
            datasets: [{
                label: 'Encryptions',
                data: [0, 0, 0, 0, 0, 0, 0, 0],
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                tension: 0.4
            }, {
                label: 'Decryptions',
                data: [0, 0, 0, 0, 0, 0, 0, 0],
                borderColor: 'rgba(153, 102, 255, 1)',
                backgroundColor: 'rgba(153, 102, 255, 0.2)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Count'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Date'
                    }
                }
            }
        }
    });
}

/**
 * Create methods comparison chart
 */
function createMethodsChart() {
    const ctx = document.getElementById('methodsChart').getContext('2d');
    methodsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['LSB', 'PVD', 'DCT', 'DWT'],
            datasets: [{
                label: 'Usage Count',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(75, 192, 192, 0.5)',
                    'rgba(54, 162, 235, 0.5)',
                    'rgba(153, 102, 255, 0.5)',
                    'rgba(255, 159, 64, 0.5)'
                ],
                borderColor: [
                    'rgba(75, 192, 192, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(153, 102, 255, 1)',
                    'rgba(255, 159, 64, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Count'
                    }
                }
            }
        }
    });
}

/**
 * Load trend data from the server
 */
function loadTrends() {
    console.log('Loading trends data...');
    
    // Show loading indicators
    showLoading(true);
    
    // Fix the endpoint URL - change from /admin_bp/api/analytics/trends to /admin/api/analytics/trends
    fetch('/admin/api/analytics/trends', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json'
        },
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Trends data received:', data);
        if (data.success) {
            updateTrendDisplay(data);
        } else {
            showError('Failed to load trends: ' + data.message);
            console.error('Failed to load trends:', data.message);
        }
        showLoading(false);
    })
    .catch(error => {
        showError('Error loading analytics data: ' + error.message);
        console.error('Error loading trends:', error);
        showLoading(false);
    });
}

/**
 * Update trend displays with data from the server
 */
function updateTrendDisplay(data) {
    // Update usage chart if it exists
    if (usageChart) {
        usageChart.data.datasets[0].data = data.encryption_trend || [0,0,0,0,0,0,0,0];
        usageChart.data.datasets[1].data = data.decryption_trend || [0,0,0,0,0,0,0,0];
        usageChart.update();
    }
    
    // Update methods chart if it exists
    if (methodsChart) {
        // Add safety checks to prevent "undefined is not an object" errors
        const methodCounts = data.method_counts || {};
        methodsChart.data.datasets[0].data = [
            methodCounts.LSB || 0,
            methodCounts.PVD || 0,
            methodCounts.DCT || 0,
            methodCounts.DWT || 0
        ];
        methodsChart.update();
    }
    
    // Update summary stats
    updateStatDisplay('total-encryptions', data.total_encryptions || 0);
    updateStatDisplay('total-decryptions', data.total_decryptions || 0);
    updateStatDisplay('total-users', data.total_users || 0);
    updateStatDisplay('active-users', data.active_users || 0);
}

/**
 * Update a stat display element if it exists
 */
function updateStatDisplay(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

// Add these new helper functions
function showError(message) {
    const container = document.querySelector('.analytics-container');
    if (!container) return;
    
    // Create error alert if it doesn't exist
    let errorAlert = document.getElementById('analytics-error');
    if (!errorAlert) {
        errorAlert = document.createElement('div');
        errorAlert.id = 'analytics-error';
        errorAlert.className = 'alert alert-danger';
        errorAlert.role = 'alert';
        container.prepend(errorAlert);
    }
    
    errorAlert.textContent = message;
    errorAlert.style.display = 'block';
}

function showLoading(isLoading) {
    // Update stat displays with loading indicators
    const statElements = ['total-encryptions', 'total-decryptions', 'total-users', 'active-users'];
    
    statElements.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = isLoading ? 'Loading...' : '--';
        }
    });
}

// Initialize analytics when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on an analytics page
    console.log('DOM loaded, checking for analytics container');
    if (document.querySelector('.analytics-container')) {
        console.log('Analytics container found, initializing');
        initAnalytics();
    } else {
        console.log('No analytics container found on this page');
    }
});
