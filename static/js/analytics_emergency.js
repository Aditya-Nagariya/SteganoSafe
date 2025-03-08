/**
 * Emergency Analytics Script
 * This is a last-resort script to ensure analytics always displays something
 */

(function() {
    // Execute immediately
    console.log("Emergency analytics script activated");

    // Constants
    const LOAD_TIMEOUT = 2000; // Wait 2 seconds, then show something
    
    // Create static HTML that will always work
    function createEmergencyContent() {
        return `
            <div style="max-width: 1200px; margin: 0 auto; padding: 20px;">
                <div style="margin-bottom: 20px;">
                    <h2>Analytics Dashboard</h2>
                    <p style="color: #664d03; background-color: #fff3cd; padding: 10px; border-radius: 4px;">
                        <strong>Note:</strong> Displaying emergency static content. The regular analytics may be experiencing issues.
                    </p>
                </div>

                <div style="display: flex; flex-wrap: wrap; margin: -10px;">
                    <div style="flex: 1; min-width: 200px; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin: 10px; padding: 15px; border-radius: 4px; text-align: center;">
                        <h5>Total Users</h5>
                        <div style="font-size: 24px; font-weight: bold;">42</div>
                    </div>
                    <div style="flex: 1; min-width: 200px; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin: 10px; padding: 15px; border-radius: 4px; text-align: center;">
                        <h5>Encryptions</h5>
                        <div style="font-size: 24px; font-weight: bold;">150</div>
                    </div>
                    <div style="flex: 1; min-width: 200px; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin: 10px; padding: 15px; border-radius: 4px; text-align: center;">
                        <h5>Decryptions</h5>
                        <div style="font-size: 24px; font-weight: bold;">85</div>
                    </div>
                    <div style="flex: 1; min-width: 200px; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin: 10px; padding: 15px; border-radius: 4px; text-align: center;">
                        <h5>Active Users</h5>
                        <div style="font-size: 24px; font-weight: bold;">18</div>
                    </div>
                </div>

                <div style="background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-top: 20px; padding: 15px; border-radius: 4px;">
                    <h3>Action Required</h3>
                    <p>The analytics dashboard is not loading correctly. Please try the following:</p>
                    <ul>
                        <li>Check server logs for errors</li>
                        <li>Verify that the database is accessible</li>
                        <li>Check for JavaScript console errors</li>
                        <li>Try clearing your browser cache</li>
                    </ul>
                    <button onclick="window.location.reload()" style="background: #0d6efd; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
                        Refresh Page
                    </button>
                    <button onclick="window.location.href='/admin/'" style="background: #6c757d; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-left: 10px;">
                        Return to Dashboard
                    </button>
                </div>
            </div>
        `;
    }

    // Wait for a brief moment then check if content is visible
    setTimeout(function() {
        // Check if there's actual content displayed
        const contentDiv = document.getElementById('analytics-content');
        const loadingDiv = document.getElementById('loading');
        
        if ((!contentDiv || contentDiv.style.display === 'none') && document.body.innerHTML.length < 1000) {
            console.log("Analytics content not loaded, applying emergency content");
            document.body.innerHTML = createEmergencyContent();
        } else if (loadingDiv && loadingDiv.style.display !== 'none') {
            // Hide loading indicator if it's still showing
            loadingDiv.style.display = 'none';
            
            // Show content if it exists
            if (contentDiv) contentDiv.style.display = 'block';
            
            console.log("Analytics loading stuck - forcing content display");
        }
    }, LOAD_TIMEOUT);
    
    // Add event listener to detect if page is partially loaded
    window.addEventListener('DOMContentLoaded', function() {
        console.log("DOM content loaded - analytics emergency script prepared");
        
        // Set another timeout as safety measure
        setTimeout(function() {
            const contentDiv = document.getElementById('analytics-content');
            const loadingDiv = document.getElementById('loading');
            
            if (loadingDiv && loadingDiv.style.display !== 'none') {
                console.log("Loading still showing after timeout - hiding loader");
                loadingDiv.style.display = 'none';
                
                // Show content if it exists
                if (contentDiv) contentDiv.style.display = 'block';
            }
        }, 5000);
    });
})();
