/**
 * Admin Analytics Dashboard JavaScript
 * Handles data loading, chart rendering and interactive components
 */

// Store chart instances
let activityChart = null;
let methodsChart = null;

// Helper function to format numbers
function formatNumber(num) {
    if (num === undefined || num === null) return "-";
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Load data based on time period
function loadAnalyticsData(period = 7) {
    console.log(`Loading analytics data for period: ${period} days`);
    
    // Show loading indicator
    document.getElementById('loading').style.display = 'block';
    document.getElementById('analytics-content').style.display = 'none';
    
    // Update active state on period buttons
    document.querySelectorAll('.period-selector').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-period') == period) {
            btn.classList.add('active');
        }
    });
    
    // Default to test endpoint if we're debugging
    const apiUrl = `/admin/api/analytics/test`;
    console.log(`Fetching analytics data from: ${apiUrl}`);
    
    // Log to debug overlay if it exists
    if (window.logToDebugOverlay) {
        window.logToDebugOverlay(`Starting analytics data fetch from: ${apiUrl}`);
    }
    
    fetch(apiUrl)
        .then(response => {
            console.log('API response status:', response.status);
            if (!response.ok) {
                throw new Error(`Network response was not ok: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Analytics data received:', data);
            
            if (window.logToDebugOverlay) {
                window.logToDebugOverlay('Analytics API response received');
            }
            
            if (data.success) {
                try {
                    updateDashboard(data);
                    document.getElementById('loading').style.display = 'none';
                    document.getElementById('analytics-content').style.display = 'block';
                } catch (error) {
                    console.error('Error processing analytics data:', error);
                    displayErrorMessage('Error processing analytics data: ' + error.message);
                }
            } else {
                console.error('Error in analytics data:', data.error);
                displayErrorMessage('Error loading analytics data: ' + (data.error || 'Unknown error'));
                document.getElementById('loading').style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error fetching analytics data:', error);
            displayErrorMessage('Failed to load analytics data: ' + error.message);
            document.getElementById('loading').style.display = 'none';
        });
}

// Display error message in analytics dashboard
function displayErrorMessage(message) {
    document.getElementById('loading').style.display = 'none';
    
    const errorContainer = document.createElement('div');
    errorContainer.classList.add('alert', 'alert-danger', 'my-4');
    errorContainer.innerHTML = `
        <h4 class="alert-heading">Error Loading Data</h4>
        <p>${message}</p>
        <hr>
        <p class="mb-0">Try refreshing the page or selecting a different time period.</p>
    `;
    
    const content = document.getElementById('analytics-content');
    content.innerHTML = '';
    content.style.display = 'block';
    content.appendChild(errorContainer);
}

// Update dashboard with fetched data
function updateDashboard(data) {
    const summary = data.summary;
    
    // Update summary stats
    document.getElementById('stat-total-users').textContent = formatNumber(summary.total_users);
    document.getElementById('stat-total-encryptions').textContent = formatNumber(summary.encryptions);
    document.getElementById('stat-total-decryptions').textContent = formatNumber(summary.decryptions);
    document.getElementById('stat-active-users').textContent = formatNumber(summary.active_users);
    
    // Update trends
    updateTrendElement('stat-users-trend', summary.new_users_trend);
    updateTrendElement('stat-encryptions-trend', summary.encryptions_trend);
    updateTrendElement('stat-decryptions-trend', summary.decryptions_trend);
    updateTrendElement('stat-active-users-trend', summary.active_users_trend);
    
    // Update charts
    updateActivityChart(data.daily_activity);
    updateMethodsChart(data.method_counts);
    
    // Update top users table
    updateTopUsersTable(data.top_users);
}

// Update trend indicator
function updateTrendElement(elementId, trendValue) {
    const element = document.getElementById(elementId);
    if (!element) {
        console.error(`Trend element not found: ${elementId}`);
        return;
    }
    
    if (trendValue > 0) {
        element.innerHTML = `<i class="fas fa-arrow-up"></i> ${trendValue}%`;
        element.className = 'stats-growth positive';
    } else if (trendValue < 0) {
        element.innerHTML = `<i class="fas fa-arrow-down"></i> ${Math.abs(trendValue)}%`;
        element.className = 'stats-growth negative';
    } else {
        element.innerHTML = `<i class="fas fa-minus"></i> 0%`;
        element.className = 'stats-growth neutral';
    }
}

// Update activity chart
function updateActivityChart(dailyActivity) {
    const ctx = document.getElementById('activityChart');
    if (!ctx) {
        console.error('Activity chart canvas not found!');
        return;
    }
    
    try {
        const labels = dailyActivity.map(day => day.label);
        const encryptionData = dailyActivity.map(day => day.encryptions);
        const decryptionData = dailyActivity.map(day => day.decryptions);
        
        if (activityChart) {
            activityChart.destroy();
        }
        
        activityChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Encryptions',
                        data: encryptionData,
                        borderColor: '#0d6efd',
                        backgroundColor: 'rgba(13, 110, 253, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: 'Decryptions',
                        data: decryptionData,
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error updating activity chart:', error);
        ctx.parentNode.innerHTML = `<div class="alert alert-warning">Error loading chart: ${error.message}</div>`;
    }
}

// Update methods chart
function updateMethodsChart(methodCounts) {
    const ctx = document.getElementById('methodsChart');
    if (!ctx) return;
    
    if (!methodCounts) {
        console.error('Method counts data is missing');
        return;
    }
    
    const methods = Object.keys(methodCounts);
    const counts = Object.values(methodCounts);
    
    if (methodsChart) {
        methodsChart.destroy();
    }
    
    methodsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: methods,
            datasets: [{
                data: counts,
                backgroundColor: [
                    'rgba(13, 110, 253, 0.7)',
                    'rgba(25, 135, 84, 0.7)',
                    'rgba(255, 193, 7, 0.7)',
                    'rgba(220, 53, 69, 0.7)'
                ],
                borderColor: '#fff',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                }
            }
        }
    });
}

// Update top users table
function updateTopUsersTable(users) {
    const tableBody = document.getElementById('top-users-table');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    if (!users || users.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="5" class="text-center">No user activity in this period</td>';
        tableBody.appendChild(row);
        return;
    }
    
    users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>
                <div class="d-flex align-items-center">
                    <div class="user-avatar bg-primary text-white rounded-circle me-3" style="width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; font-weight: bold;">${user.initials || 'UN'}</div>
                    <div>
                        <h6 class="mb-0">${user.username}</h6>
                        <small class="text-muted">ID: ${user.id}</small>
                    </div>
                </div>
            </td>
            <td>${formatNumber(user.activity_count)}</td>
            <td>${formatNumber(user.encryptions)}</td>
            <td>${formatNumber(user.decryptions)}</td>
            <td>${user.last_active}</td>
        `;
        tableBody.appendChild(row);
    });
}

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Admin analytics script initialized');

    // Force immediate loading using the test endpoint
    setTimeout(() => {
        loadAnalyticsData(7);
    }, 100);
    
    // Set up event listeners for period selectors
    const selectors = document.querySelectorAll('.period-selector');
    selectors.forEach(selector => {
        selector.addEventListener('click', function() {
            const period = this.getAttribute('data-period');
            loadAnalyticsData(period);
            
            // Update URL without reloading
            const url = new URL(window.location);
            url.searchParams.set('period', period);
            window.history.pushState({}, '', url);
        });
    });
});

// Expose functions to global scope for debugging
window.loadAnalyticsData = loadAnalyticsData;
window.displayErrorMessage = displayErrorMessage;
window.updateDashboard = updateDashboard;
