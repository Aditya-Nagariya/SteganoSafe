/**
 * Analytics dashboard JavaScript for the SteganoSafe application.
 * This file handles charts, data visualization, and interactions.
 */

// Initialize charts and data on document load
document.addEventListener('DOMContentLoaded', function() {
    // Maintain state
    let appState = {
        selectedPeriod: '7',
        isLoading: false,
        charts: {},
        lastRefreshTime: new Date()
    };
    
    // Initialize charts
    initCharts();
    
    // Set up event listeners
    setupEventListeners();
    
    // Load initial data
    loadAnalyticsData(appState.selectedPeriod);
    
    // Update the "last updated" time every minute
    setInterval(updateLastUpdatedTime, 60000);
    
    /**
     * Initialize charts with empty data
     */
    function initCharts() {
        // Activity chart (line chart)
        const activityChartCtx = document.getElementById('activityChart');
        if (activityChartCtx) {
            appState.charts.activity = new Chart(activityChartCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Encryptions',
                            data: [],
                            borderColor: '#2c7da0',
                            backgroundColor: 'rgba(44, 125, 160, 0.2)',
                            tension: 0.3,
                            fill: true
                        },
                        {
                            label: 'Decryptions',
                            data: [],
                            borderColor: '#38b000',
                            backgroundColor: 'rgba(56, 176, 0, 0.2)',
                            tension: 0.3,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        intersect: false,
                        mode: 'index'
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    },
                    plugins: {
                        tooltip: {
                            enabled: true
                        },
                        legend: {
                            position: 'top',
                            labels: {
                                usePointStyle: true,
                                padding: 15
                            }
                        }
                    }
                }
            });
        }
        
        // Distribution chart (doughnut)
        const distributionChartCtx = document.getElementById('distributionChart');
        if (distributionChartCtx) {
            appState.charts.distribution = new Chart(distributionChartCtx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Encryptions', 'Decryptions', 'User Actions', 'Other'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            '#2c7da0',
                            '#38b000',
                            '#ffba08',
                            '#d90429'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 20
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    },
                    cutout: '70%',
                    animation: {
                        animateRotate: true,
                        animateScale: true
                    }
                }
            });
        }
        
        // User growth chart (if exists)
        const userGrowthChartCtx = document.getElementById('userGrowthChart');
        if (userGrowthChartCtx) {
            appState.charts.userGrowth = new Chart(userGrowthChartCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'New Users',
                        data: [],
                        backgroundColor: 'rgba(54, 162, 235, 0.5)',
                        borderColor: 'rgb(54, 162, 235)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
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
        }
    }
    
    /**
     * Set up event listeners for UI interactions
     */
    function setupEventListeners() {
        // Time period selector
        const periodButtons = document.querySelectorAll('.period-btn');
        if (periodButtons.length > 0) {
            periodButtons.forEach(button => {
                button.addEventListener('click', function() {
                    if (appState.isLoading) return;
                    
                    const period = this.dataset.period;
                    
                    // Update active state
                    periodButtons.forEach(btn => btn.classList.remove('active'));
                    this.classList.add('active');
                    
                    appState.selectedPeriod = period;
                    
                    // Fetch data for the selected period
                    loadAnalyticsData(period);
                });
            });
        } else {
            // Add period selector if it doesn't exist
            createTimePeriodSelector();
        }
        
        // Refresh button
        const refreshButton = document.getElementById('refresh-data');
        if (refreshButton) {
            refreshButton.addEventListener('click', function() {
                if (appState.isLoading) return;
                
                const button = this;
                const originalText = button.innerHTML;
                
                button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Refreshing...';
                button.disabled = true;
                
                loadAnalyticsData(appState.selectedPeriod, function() {
                    button.innerHTML = originalText;
                    button.disabled = false;
                });
            });
        }
    }
    
    /**
     * Create time period selector if it doesn't exist
     */
    function createTimePeriodSelector() {
        const headerSection = document.querySelector('.container-fluid > .row:first-child');
        if (headerSection) {
            const periodSelector = document.createElement('div');
            periodSelector.className = 'row mb-3';
            periodSelector.innerHTML = `
                <div class="col-12">
                    <div class="btn-group" role="group">
                        <button type="button" class="btn btn-outline-primary period-btn active" data-period="7">7 Days</button>
                        <button type="button" class="btn btn-outline-primary period-btn" data-period="14">14 Days</button>
                        <button type="button" class="btn btn-outline-primary period-btn" data-period="30">30 Days</button>
                        <button type="button" class="btn btn-outline-primary period-btn" data-period="90">90 Days</button>
                    </div>
                    <small class="text-muted ms-2" id="last-updated"></small>
                </div>
            `;
            
            headerSection.parentNode.insertBefore(periodSelector, headerSection.nextSibling);
            
            // Add event listeners to new buttons
            periodSelector.querySelectorAll('.period-btn').forEach(button => {
                button.addEventListener('click', function() {
                    if (appState.isLoading) return;
                    
                    const period = this.dataset.period;
                    
                    // Update active state
                    periodSelector.querySelectorAll('.period-btn').forEach(btn => btn.classList.remove('active'));
                    this.classList.add('active');
                    
                    appState.selectedPeriod = period;
                    
                    // Fetch data for the selected period
                    loadAnalyticsData(period);
                });
            });
        }
    }
    
    /**
     * Load analytics data from the server
     * @param {string} days - Number of days for the time period
     * @param {function} callback - Optional callback function
     */
    function loadAnalyticsData(days = '7', callback) {
        if (appState.isLoading) return;
        
        appState.isLoading = true;
        
        // Show loading spinner in all data cards
        showLoadingSpinners();
        
        // Show a toast notification
        showNotification(`Loading data for the last ${days} days...`, 'info', 0);
        
        // Construct API URL with days parameter
        const apiUrl = `/admin/api/analytics/summary?days=${days}`;
        
        fetch(apiUrl)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log("Analytics data:", data);
                if (data.success) {
                    // Remove loading notification
                    clearNotifications();
                    
                    // Update the data displays
                    updateDashboardData(data);
                    
                    // Update last refresh time
                    appState.lastRefreshTime = new Date();
                    updateLastUpdatedTime();
                    
                    // Show success notification
                    showNotification('Analytics data updated successfully', 'success', 2000);
                } else {
                    console.error("Failed to load analytics data:", data.error);
                    showNotification(`Error: ${data.error || 'Unknown error'}`, 'danger', 0);
                }
            })
            .catch(error => {
                console.error("Error loading analytics data:", error);
                showNotification(`Error: ${error.message}`, 'danger', 0);
            })
            .finally(() => {
                appState.isLoading = false;
                if (typeof callback === 'function') {
                    callback();
                }
            });
    }
    
    /**
     * Show loading spinners in data cards
     */
    function showLoadingSpinners() {
        const spinnerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
        document.getElementById('new-users-count').innerHTML = spinnerHTML;
        document.getElementById('encryptions-count').innerHTML = spinnerHTML;
        document.getElementById('decryptions-count').innerHTML = spinnerHTML;
        document.getElementById('active-users-count').innerHTML = spinnerHTML;
    }
    
    /**
     * Update all dashboard data with the API response
     * @param {Object} data - The API response data
     */
    function updateDashboardData(data) {
        // Update summary cards
        const summary = data.summary;
        document.getElementById('new-users-count').textContent = summary.new_users || 0;
        document.getElementById('encryptions-count').textContent = summary.encryptions || 0;
        document.getElementById('decryptions-count').textContent = summary.decryptions || 0;
        document.getElementById('active-users-count').textContent = summary.active_users || 0;
        
        // Update trend indicators
        updateTrendDisplay('new-users-trend', summary.new_users_trend);
        updateTrendDisplay('encryptions-trend', summary.encryptions_trend);
        updateTrendDisplay('decryptions-trend', summary.decryptions_trend);
        updateTrendDisplay('active-users-trend', summary.active_users_trend);
        
        // Update activity chart with daily data
        if (data.daily_activity && data.daily_activity.length > 0 && appState.charts.activity) {
            appState.charts.activity.data.labels = data.daily_activity.map(day => day.label);
            appState.charts.activity.data.datasets[0].data = data.daily_activity.map(day => day.encryptions);
            appState.charts.activity.data.datasets[1].data = data.daily_activity.map(day => day.decryptions);
            appState.charts.activity.update();
        }
        
        // Update distribution chart
        if (appState.charts.distribution) {
            const totalEncryptions = summary.encryptions || 0;
            const totalDecryptions = summary.decryptions || 0;
            const userActions = Math.max(summary.active_users * 2, 0) || 0; // Estimate user actions
            const otherActions = Math.round((totalEncryptions + totalDecryptions) * 0.1) || 0;
            
            appState.charts.distribution.data.datasets[0].data = [
                totalEncryptions, 
                totalDecryptions,
                userActions,
                otherActions
            ];
            appState.charts.distribution.update();
        }
        
        // Update user growth chart if available
        if (data.user_growth && appState.charts.userGrowth) {
            appState.charts.userGrowth.data.labels = data.user_growth.labels;
            appState.charts.userGrowth.data.datasets[0].data = data.user_growth.data;
            appState.charts.userGrowth.update();
        }
        
        // Update top users table
        if (data.top_users && data.top_users.length > 0) {
            updateTopUsersTable(data.top_users);
        }
    }
    
    /**
     * Update the trend display for a metric
     * @param {string} elementId - ID of the element to update
     * @param {number} trendValue - The trend value (percentage)
     */
    function updateTrendDisplay(elementId, trendValue) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        if (trendValue > 0) {
            element.innerHTML = `<i class="bi bi-arrow-up me-1"></i> ${trendValue}%`;
            element.className = 'text-success';
        } else if (trendValue < 0) {
            element.innerHTML = `<i class="bi bi-arrow-down me-1"></i> ${Math.abs(trendValue)}%`;
            element.className = 'text-danger';
        } else {
            element.innerHTML = `<i class="bi bi-dash me-1"></i> 0%`;
            element.className = 'text-muted';
        }
    }
    
    /**
     * Update the top users table
     * @param {Array} users - Array of user data
     */
    function updateTopUsersTable(users) {
        const topUsersTable = document.getElementById('top-users-table');
        if (!topUsersTable) return;
        
        if (users.length > 0) {
            topUsersTable.innerHTML = users.map(user => `
                <tr>
                    <td>
                        <div class="d-flex align-items-center">
                            <div class="user-avatar me-2" style="background-color:#2c7da0;color:white;width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold;">${user.initials || user.username.substring(0,2).toUpperCase()}</div>
                            <a href="/admin/users/${user.id}" class="text-decoration-none">${user.username}</a>
                        </div>
                    </td>
                    <td>${user.encryptions || 0}</td>
                    <td>${user.decryptions || 0}</td>
                    <td>${user.last_active || 'Recently'}</td>
                </tr>
            `).join('');
        } else {
            topUsersTable.innerHTML = '<tr><td colspan="4" class="text-center">No user data available</td></tr>';
        }
    }
    
    /**
     * Display a notification message
     * @param {string} message - The message to display
     * @param {string} type - The type of notification (success, danger, info, etc.)
     * @param {number} duration - How long to show the notification (0 for no auto-dismiss)
     * @returns {HTMLElement} The notification element
     */
    function showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notification-container');
        if (!container) return null;
        
        // Clear existing notifications of the same type
        container.querySelectorAll(`.alert-${type}`).forEach(alert => {
            alert.remove();
        });
        
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        container.appendChild(alertDiv);
        
        // Auto-dismiss after duration (if specified)
        if (duration > 0) {
            setTimeout(() => {
                alertDiv.classList.remove('show');
                setTimeout(() => alertDiv.remove(), 300);
            }, duration);
        }
        
        return alertDiv;
    }
    
    /**
     * Clear all notifications
     */
    function clearNotifications() {
        const container = document.getElementById('notification-container');
        if (container) {
            container.innerHTML = '';
        }
    }
    
    /**
     * Update the "last updated" time display
     */
    function updateLastUpdatedTime() {
        const lastUpdatedElement = document.getElementById('last-updated');
        if (lastUpdatedElement) {
            const now = new Date();
            const diff = Math.floor((now - appState.lastRefreshTime) / 1000);
            
            let timeText;
            if (diff < 60) {
                timeText = 'just now';
            } else if (diff < 3600) {
                const mins = Math.floor(diff / 60);
                timeText = `${mins} minute${mins !== 1 ? 's' : ''} ago`;
            } else {
                const hrs = Math.floor(diff / 3600);
                timeText = `${hrs} hour${hrs !== 1 ? 's' : ''} ago`;
            }
            
            lastUpdatedElement.textContent = `Last updated: ${timeText}`;
        }
    }
});
