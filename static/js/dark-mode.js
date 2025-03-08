/**
 * Dark Mode Manager
 * Handles toggling and persisting dark mode preference
 */

// Self-executing function to avoid polluting global scope
(function() {
    // Keys used for storing preference
    const DARK_MODE_KEY = 'admin_dark_mode_enabled';
    
    // Debug flag - set to true to see debug messages
    const DEBUG = true;
    
    // Function to get cookie value
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }
    
    // Function to set cookie value
    function setCookie(name, value, days) {
        const maxAge = days ? days * 24 * 60 * 60 : 31536000; // Default to 1 year
        document.cookie = `${name}=${value}; path=/; max-age=${maxAge}`;
    }
    
    // Debug logger
    function debug(...args) {
        if (DEBUG) console.log('[DarkMode]', ...args);
    }
    
    // Function to toggle dark mode
    function toggleDarkMode(enableDark, updateServer = true) {
        debug(`Toggling dark mode: ${enableDark}`);
        
        // Force boolean type
        enableDark = !!enableDark;
        
        // Update body class - make sure it's directly on the body element
        if (enableDark) {
            document.documentElement.classList.add('dark-mode');
            document.body.classList.add('dark-mode');
        } else {
            document.documentElement.classList.remove('dark-mode');
            document.body.classList.remove('dark-mode');
        }
        
        // Update all toggle switches, not just one
        document.querySelectorAll('[id^="darkMode"]').forEach(toggle => {
            if (toggle.type === 'checkbox') {
                toggle.checked = enableDark;
            }
        });
        
        // Save preference to both localStorage and cookies for compatibility
        localStorage.setItem(DARK_MODE_KEY, enableDark ? 'true' : 'false');
        setCookie('dark_mode', enableDark ? '1' : '0');
        
        // Dispatch event for other scripts that might need to know
        document.dispatchEvent(new CustomEvent('darkModeChange', { 
            detail: { darkMode: enableDark } 
        }));
        
        // Log the current state of the body classes to help debugging
        debug('Body classes after toggle:', document.body.className);
        
        // Notify user of mode change
        const modeText = enableDark ? 'Dark' : 'Light';
        
        if (typeof Swal === 'function') {
            // Silent toast using SweetAlert if available
            const Toast = Swal.mixin({
                toast: true,
                position: 'bottom-end',
                showConfirmButton: false,
                timer: 2000,
                timerProgressBar: true
            });
            
            Toast.fire({
                icon: 'success',
                title: `Switched to ${modeText} Mode`
            });
        }
    }
    
    // Function to load preference
    function loadDarkModePreference() {
        debug('Loading dark mode preference');
        
        // Check for Flask-set dark_mode first (server-side)
        const bodyHasDarkMode = document.body.classList.contains('dark-mode');
        debug('Body has dark-mode class:', bodyHasDarkMode);
        
        // Then check cookie (set by both Flask and JS)
        const cookieValue = getCookie('dark_mode');
        debug('Cookie dark_mode value:', cookieValue);
        
        // Then check localStorage (JS-only)
        const localStorageValue = localStorage.getItem(DARK_MODE_KEY);
        debug('LocalStorage dark mode value:', localStorageValue);
        
        // Priority: body class > cookie > localStorage > system preference
        if (bodyHasDarkMode) {
            debug('Using body class preference');
            toggleDarkMode(true, false); // Don't update server as it already knows
        } else if (cookieValue === '1') {
            debug('Using cookie preference (enabled)');
            toggleDarkMode(true, false);
        } else if (cookieValue === '0') {
            debug('Using cookie preference (disabled)');
            toggleDarkMode(false, false);
        } else if (localStorageValue === 'true') {
            debug('Using localStorage preference (enabled)');
            toggleDarkMode(true);
        } else if (localStorageValue === 'false') {
            debug('Using localStorage preference (disabled)');
            toggleDarkMode(false);
        } else {
            // If no preference is saved, check for system preference
            const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            debug('No saved preference, using system preference:', prefersDark);
            toggleDarkMode(prefersDark);
        }
    }
    
    // Initialize as early as possible
    function init() {
        debug('Initializing dark mode manager');
        
        // Load saved preference
        loadDarkModePreference();
        
        // Set up event listeners for all dark mode toggles
        document.querySelectorAll('[id^="darkMode"]').forEach(toggle => {
            debug('Found toggle element:', toggle.id);
            toggle.addEventListener('change', function() {
                debug('Toggle changed to:', this.checked);
                toggleDarkMode(this.checked);
            });
        });
        
        // Add a listener for system preference changes
        if (window.matchMedia) {
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                // Only apply if user hasn't set a preference
                if (!localStorage.getItem(DARK_MODE_KEY) && !getCookie('dark_mode')) {
                    debug('System preference changed to:', e.matches ? 'dark' : 'light');
                    toggleDarkMode(e.matches);
                }
            });
        }
    }
    
    // Initialize when DOM is interactive for faster perceived performance
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    // Also ensure it runs after full load (belt and suspenders approach)
    window.addEventListener('load', function() {
        // Verify dark mode is correctly applied after page is fully loaded
        const shouldBeDark = document.body.classList.contains('dark-mode');
        debug('Verifying dark mode after load. Should be dark:', shouldBeDark);
        
        const isDark = document.body.classList.contains('dark-mode');
        if (shouldBeDark !== isDark) {
            debug('Dark mode state mismatch, reapplying');
            toggleDarkMode(shouldBeDark, false);
        }
    });
    
    // Expose public functions
    window.DarkModeManager = {
        toggle: toggleDarkMode,
        getPreference: () => document.body.classList.contains('dark-mode'),
        debug: () => {
            DEBUG = true;
            console.log('Dark mode debugging enabled');
            console.log('Current state:', document.body.classList.contains('dark-mode') ? 'DARK' : 'LIGHT');
            console.log('Cookie value:', getCookie('dark_mode'));
            console.log('localStorage value:', localStorage.getItem(DARK_MODE_KEY));
        }
    };
})();
