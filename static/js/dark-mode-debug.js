/**
 * Minimal Dark Mode Debugger
 */
(function() {
    console.log('Dark mode debugger loaded');
    
    // Check current state
    const isDarkMode = document.body.classList.contains('dark-mode');
    console.log('Current dark mode state:', isDarkMode);
    
    // Simple toggle function
    function toggleDarkMode(enable) {
        if (enable) {
            document.documentElement.classList.add('dark-mode');
            document.body.classList.add('dark-mode');
        } else {
            document.documentElement.classList.remove('dark-mode');
            document.body.classList.remove('dark-mode');
        }
        
        // Store preference
        localStorage.setItem('admin_dark_mode_enabled', enable ? 'true' : 'false');
        document.cookie = `dark_mode=${enable ? '1' : '0'}; path=/; max-age=31536000`;
        
        console.log('Dark mode toggled:', enable);
    }
    
    // Add simple toggle button for testing
    document.addEventListener('DOMContentLoaded', function() {
        // Find toggle switch
        const toggle = document.getElementById('darkModeToggle');
        if (toggle) {
            console.log('Found dark mode toggle');
            toggle.addEventListener('change', function() {
                console.log('Toggle clicked, new state:', this.checked);
                toggleDarkMode(this.checked);
            });
        } else {
            console.log('Dark mode toggle not found');
        }
    });
    
    // Expose for debugging in console
    window.debugDarkMode = {
        toggle: toggleDarkMode,
        getState: () => document.body.classList.contains('dark-mode')
    };
})();
