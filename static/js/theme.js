/**
 * Theme helper functions
 */

document.addEventListener('DOMContentLoaded', function() {
    // Apply theme color to meta theme-color for mobile browsers
    const metaThemeColor = document.querySelector('meta[name="theme-color"]');
    if (!metaThemeColor) {
        const meta = document.createElement('meta');
        meta.name = "theme-color";
        meta.content = "#2c7da0"; // Primary color
        document.head.appendChild(meta);
    } else {
        metaThemeColor.content = "#2c7da0";
    }

    // Detect dark mode preference from localStorage or system preference
    function detectDarkMode() {
        const savedPreference = localStorage.getItem('admin_dark_mode_enabled');
        
        if (savedPreference === 'true') {
            return true;
        } else if (savedPreference === 'false') {
            return false;
        } else {
            // If no saved preference, check system preference
            return window.matchMedia && 
                   window.matchMedia('(prefers-color-scheme: dark)').matches;
        }
    }
    
    // Apply dark mode if detected
    if (detect
