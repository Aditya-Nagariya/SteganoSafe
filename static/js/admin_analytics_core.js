/**
 * Admin Analytics Core - Essential functions for data loading and display
 * Prioritizes loading real data while providing fallbacks
 */

// Sample data as fallback only
const SAMPLE_ANALYTICS_DATA = {
    success: true,
    days: 7,
    summary: {
        total_users: 42,
        verified_users: 35,
        new_users: 7,
        new_users_trend: 25,
        encryptions: 150,
        encryptions_trend: 30,
        decryptions: 85,
        decryptions_trend: 15,
        active_users: 18,
        active_users_trend: 20
    },
    top_users: [
        {
            id: 1,
            username: 'admin',
            initials: 'AD',
            activity_count: 45,
            encryptions: 30,
            decryptions: 15,
            last_active: 'Just now'
        },
        {
            id: 2,
            username: 'user1',
            initials: 'U1',
            activity_count: 30,
            encryptions: 20,
            decryptions: 10,
            last_active: '2h ago'
        },
        {
            id: 3,
            username: 'user2',
            initials: 'U2',
            activity_count: 20,
            encryptions: 12,
            decryptions: 8,
            last_active: '1d ago'
        }
    ],
    daily_activity: [
        {date: '2025-03-02', label: 'Mar 02', encryptions: 15, decryptions: 8, total: 23},
        {date: '2025-03-03', label: 'Mar 03', encryptions: 18, decryptions: 10, total: 28},
        {date: '2025-03-04', label: 'Mar 04', encryptions: 20, decryptions: 12, total: 32},
        {date: '2025-03-05', label: 'Mar 05', encryptions: 25, decryptions: 15, total: 40},
        {date: '2025-03-06', label: 'Mar 06', encryptions: 22, decryptions: 13, total: 35},
        {date: '2025-03-07', label: 'Mar 07', encryptions: 28, decryptions: 16, total: 44},
        {date: '2025-03-08', label: 'Mar 08', encryptions: 22, decryptions: 11, total: 33}
    ],
    method_counts: {
        'LSB': 60,
        'DCT': 25,
        'PVD': 10,
        'DWT': 15
    }
};

// Format numbers with commas
function formatNumber(num) {
    if (num === undefined || num === null) return "-";
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Load analytics data from API with better error reporting
function loadAnalyticsData(period = 7, callback) {
    console.log(`Loading analytics data for ${period} days...`);
    
    // Sample data only used as ultimate backup
    const sampleData = SAMPLE_ANALYTICS_DATA;
    let timeoutFired = false;
    
    // Set a timeout as a safety net - CRITICAL FIX: shorter timeout and flag to track if it fired
    const dataTimeout = setTimeout(() => {
        console.log("API request timed out - using sample data");
        timeoutFired = true;
        callback(sampleData, true); // Pass true to indicate it's fallback data
    }, 5000); // Reduced timeout to 5 seconds for better UX
    
    // CRITICAL FIX: Add error handling for fetch API
    try {
        // First try the full analytics endpoint that queries the database
        fetch(`/admin/api/analytics/summary?days=${period}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`API returned status ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // CRITICAL FIX: Don't update if timeout already fired
                if (timeoutFired) return;
                
                clearTimeout(dataTimeout);
                if (!data.success) {
                    throw new Error(data.error || 'Invalid data format');
                }
                
                console.log(`Data loaded successfully from database`);
                callback(data, false); // Real data
            })
            .catch(error => {
                console.warn(`Real data endpoint failed:`, error.message);
                
                // CRITICAL FIX: Check if timeout already fired
                if (timeoutFired) return;
                
                // Try the direct-test endpoint as a fallback
                fetch(`/admin/api/analytics/direct-test?days=${period}`)
                    .then(response => {
                        if (!response.ok) {
                            throw new Error(`API returned status ${response.status}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        // CRITICAL FIX: Check if timeout already fired
                        if (timeoutFired) return;
                        
                        clearTimeout(dataTimeout);
                        
                        if (!data.success) {
                            throw new Error(data.error || 'Invalid data format');
                        }
                        
                        console.log(`Data loaded from direct-test endpoint`);
                        callback(data, true); // Indicate it's fallback data
                    })
                    .catch(fallbackError => {
                        // CRITICAL FIX: Check if timeout already fired
                        if (timeoutFired) return;
                        
                        console.error("All API endpoints failed:", fallbackError);
                        clearTimeout(dataTimeout);
                        callback(sampleData, true); // Ultimate fallback
                    });
            });
    } catch (e) {
        // CRITICAL FIX: Handle synchronous errors in the fetch call itself
        console.error("Fatal error in fetch API:", e);
        if (!timeoutFired) {
            clearTimeout(dataTimeout);
            callback(sampleData, true);
        }
    }
}

// Try a single API endpoint
function tryApiEndpoint(url) {
    return fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error(`API returned status ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (!data || !data.success) {
                throw new Error("Invalid data format");
            }
            console.log(`Data loaded successfully from ${url}`);
            return data;
        })
        .catch(error => {
            console.warn(`Endpoint ${url} failed:`, error.message);
            return null; // Return null to indicate failure
        });
}

// Create chart if Chart.js is available
function createChart(ctx, config) {
    try {
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not available');
            return null;
        }
        
        return new Chart(ctx, config);
    } catch (error) {
        console.error('Error creating chart:', error);
        return null;
    }
}

// Update trend indicator
function updateTrendIndicator(element, value) {
    if (!element) return;
    
    if (value > 0) {
        element.innerHTML = `<i class="bi bi-arrow-up"></i> ${value}%`;
        element.className = 'stats-growth positive';
    } else if (value < 0) {
        element.innerHTML = `<i class="bi bi-arrow-down"></i> ${Math.abs(value)}%`;
        element.className = 'stats-growth negative';
    } else {
        element.innerHTML = `<i class="bi bi-dash"></i> 0%`;
        element.className = 'stats-growth neutral';
    }
}

// Export the analytics functions
window.AnalyticsCore = {
    loadData: loadAnalyticsData,
    formatNumber: formatNumber,
    createChart: createChart,
    updateTrend: updateTrendIndicator,
    sampleData: SAMPLE_ANALYTICS_DATA
};
