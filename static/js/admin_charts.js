/**
 * Admin Dashboard Charts
 * Interactive visualizations for the SteganoSafe admin interface
 */

document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the admin dashboard
    const activityChartEl = document.getElementById('activityChart');
    const encryptionChartEl = document.getElementById('encryptionChart');
    const userGrowthChartEl = document.getElementById('userGrowthChart');
    
    // Activity Chart
    if (activityChartEl) {
        const activityCtx = activityChartEl.getContext('2d');
        const activityChart = new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                datasets: [{
                    label: 'User Registrations',
                    data: [12, 19, 13, 25, 32, 38, 42],
                    borderColor: '#4e54c8',
                    backgroundColor: 'rgba(78, 84, 200, 0.1)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'Encoded Images',
                    data: [5, 12, 17, 25, 24, 35, 37],
                    borderColor: '#0acf97',
                    backgroundColor: 'rgba(10, 207, 151, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(49, 58, 70, 0.9)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        borderColor: 'rgba(255, 255, 255, 0.2)',
                        borderWidth: 1,
                        padding: 10,
                        titleFont: {
                            size: 14,
                            weight: 'bold'
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'nearest'
                }
            }
        });
    }
    
    // Encryption Chart
    if (encryptionChartEl) {
        const encryptionCtx = encryptionChartEl.getContext('2d');
        const encryptionChart = new Chart(encryptionCtx, {
            type: 'doughnut',
            data: {
                labels: ['LSB', 'DCT', 'DWT'],
                datasets: [{
                    data: [65, 20, 15],
                    backgroundColor: [
                        '#4e54c8',
                        '#0acf97',
                        '#fa5c7c'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        backgroundColor: 'rgba(49, 58, 70, 0.9)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        padding: 10
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
    
    // User Growth Chart (for user detail page)
    if (userGrowthChartEl) {
        const userGrowthCtx = userGrowthChartEl.getContext('2d');
        const userGrowthChart = new Chart(userGrowthCtx, {
            type: 'bar',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Activity',
                    data: [4, 7, 3, 5, 9, 12, 8],
                    backgroundColor: 'rgba(78, 84, 200, 0.6)',
                    borderColor: '#4e54c8',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                barThickness: 12,
                borderRadius: 4
            }
        });
    }
});
