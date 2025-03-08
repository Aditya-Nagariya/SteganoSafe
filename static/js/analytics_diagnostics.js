/**
 * Analytics Dashboard Diagnostic Tool
 * Helps troubleshoot loading and rendering issues
 */

class AnalyticsDiagnostics {
    constructor() {
        this.diagnosticData = {
            browserInfo: {},
            apiChecks: {},
            renderingChecks: {},
            errors: []
        };
        
        this.initialize();
    }
    
    initialize() {
        // Collect browser info
        this.collectBrowserInfo();
        
        // Monitor for errors
        this.setupErrorMonitoring();
        
        console.log("Analytics diagnostics initialized");
    }
    
    collectBrowserInfo() {
        const nav = window.navigator;
        
        this.diagnosticData.browserInfo = {
            userAgent: nav.userAgent,
            platform: nav.platform,
            language: nav.language,
            cookiesEnabled: nav.cookieEnabled,
            screenWidth: window.screen.width,
            screenHeight: window.screen.height,
            availableAPIs: {
                fetch: typeof fetch !== 'undefined',
                localStorage: typeof localStorage !== 'undefined',
                sessionStorage: typeof sessionStorage !== 'undefined',
                indexedDB: typeof indexedDB !== 'undefined',
                webWorkers: typeof Worker !== 'undefined'
            }
        };
    }
    
    setupErrorMonitoring() {
        window.addEventListener('error', (event) => {
            this.logError('Uncaught error', {
                message: event.message,
                filename: event.filename,
                lineno: event.lineno,
                colno: event.colno,
                stack: event.error ? event.error.stack : null
            });
        });
        
        window.addEventListener('unhandledrejection', (event) => {
            this.logError('Unhandled promise rejection', {
                reason: event.reason ? event.reason.toString() : 'Unknown reason',
                stack: event.reason && event.reason.stack ? event.reason.stack : null
            });
        });
    }
    
    logError(type, details) {
        const error = {
            type,
            details,
            timestamp: new Date().toISOString()
        };
        
        this.diagnosticData.errors.push(error);
        console.error(`[Analytics Diagnostics] ${type}:`, details);
    }
    
    checkAPIEndpoint(url) {
        return fetch(url)
            .then(response => {
                const status = response.ok;
                const statusCode = response.status;
                
                // Try to parse as JSON if possible
                return response.text().then(text => {
                    let json = null;
                    try {
                        json = JSON.parse(text);
                    } catch (e) {
                        // Not JSON
                    }
                    
                    return {
                        url,
                        status,
                        statusCode,
                        isJSON: json !== null,
                        data: json,
                        rawLength: text.length
                    };
                });
            })
            .catch(error => {
                return {
                    url,
                    status: false,
                    error: error.message
                };
            });
    }
    
    async runAPIDiagnostics() {
        const endpoints = [
            '/admin/api/analytics/health',
            '/admin/api/analytics/direct-test',
            '/admin/api/analytics/summary'
        ];
        
        for (const endpoint of endpoints) {
            this.diagnosticData.apiChecks[endpoint] = await this.checkAPIEndpoint(endpoint);
        }
        
        return this.diagnosticData.apiChecks;
    }
    
    checkElementVisibility() {
        const elements = {
            'loading': document.getElementById('loading'),
            'analytics-content': document.getElementById('analytics-content'),
            'activity-chart': document.getElementById('activity-chart'),
            'methods-chart': document.getElementById('methods-chart')
        };
        
        const results = {};
        
        for (const [name, element] of Object.entries(elements)) {
            if (!element) {
                results[name] = {exists: false};
                continue;
            }
            
            const style = window.getComputedStyle(element);
            results[name] = {
                exists: true,
                display: style.display,
                visibility: style.visibility,
                opacity: style.opacity,
                width: element.offsetWidth,
                height: element.offsetHeight
            };
        }
        
        this.diagnosticData.renderingChecks.elementVisibility = results;
        return results;
    }
    
    exportDiagnostics() {
        // Add latest checks
        this.checkElementVisibility();
        
        return {
            timestamp: new Date().toISOString(),
            data: this.diagnosticData
        };
    }
    
    resetLoadingState() {
        const loadingElement = document.getElementById('loading');
        const contentElement = document.getElementById('analytics-content');
        
        if (loadingElement) loadingElement.style.display = 'none';
        if (contentElement) contentElement.style.display = 'block';
        
        console.log("[Analytics Diagnostics] Loading state reset");
    }
}

// Create global instance for easy access
window.analyticsDiagnostics = new AnalyticsDiagnostics();

// Add emergency reset function to window
window.resetAnalyticsLoadingState = function() {
    window.analyticsDiagnostics.resetLoadingState();
};

// Add a button to the page for emergency reset
document.addEventListener('DOMContentLoaded', function() {
    const button = document.createElement('button');
    button.id = 'emergency-reset-btn';
    button.textContent = 'Reset Loading';
    button.style.cssText = 'position: fixed; bottom: 10px; left: 10px; z-index: 99999; display: none; background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer;';
    
    button.addEventListener('click', window.resetAnalyticsLoadingState);
    
    // Show button when Shift+Alt+D is pressed
    document.addEventListener('keydown', function(e) {
        if (e.shiftKey && e.altKey && e.key === 'D') {
            button.style.display = button.style.display === 'none' ? 'block' : 'none';
        }
    });
    
    document.body.appendChild(button);
});
