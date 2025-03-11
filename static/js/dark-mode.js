/**
 * Dark Mode Manager
 * Handles theme toggling and persistence across pages
 */

// Create a global DarkModeManager
window.DarkModeManager = (function() {
    // Initialize with system preference or stored value
    let darkMode = localStorage.getItem('theme') === 'dark' || 
                   (localStorage.getItem('theme') === null && 
                    window.matchMedia('(prefers-color-scheme: dark)').matches);
    
    // Store initial state
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
    
    // Apply initial theme
    if (darkMode) {
        document.body.classList.add('dark-mode');
        document.body.classList.remove('light-mode');
    } else {
        document.body.classList.add('light-mode');
        document.body.classList.remove('dark-mode');
    }
    
    // Function to get current preference
    function getPreference() {
        return darkMode;
    }
    
    // Function to toggle theme
    function toggle(forceDark = null) {
        // If forceDark is provided, use that value, otherwise toggle the current value
        darkMode = forceDark !== null ? forceDark : !darkMode;
        
        // Update localStorage
        localStorage.setItem('theme', darkMode ? 'dark' : 'light');
        
        // Apply theme to body
        if (darkMode) {
            document.body.classList.add('dark-mode');
            document.body.classList.remove('light-mode');
        } else {
            document.body.classList.add('light-mode');
            document.body.classList.remove('dark-mode');
        }
        
        // Dispatch event for other scripts to listen for
        document.dispatchEvent(new CustomEvent('darkModeChange', { 
            detail: { darkMode: darkMode }
        }));
        
        return darkMode;
    }
    
    // Set up system preference change listener
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)')
            .addEventListener('change', event => {
                // Only auto-switch if user hasn't manually set a preference
                if (localStorage.getItem('theme') === null) {
                    toggle(event.matches);
                }
            });
    }
    
    // Public API
    return {
        toggle: toggle,
        getPreference: getPreference
    };
})();

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dark mode manager initialized');
    
    // Find all theme toggle buttons
    const themeToggles = document.querySelectorAll('[data-theme-toggle]');
    themeToggles.forEach(btn => {
        // Update button UI based on current theme
        updateToggleButtonUI(btn);
        
        // Add click handler
        btn.addEventListener('click', function() {
            window.DarkModeManager.toggle();
            updateToggleButtonUI(btn);
        });
    });
    
    // Look for themeToggle button as well (from templates/admin/components/topbar.html)
    const themeToggleBtn = document.getElementById('themeToggle');
    if (themeToggleBtn) {
        updateToggleButtonUI(themeToggleBtn);
        
        themeToggleBtn.addEventListener('click', function() {
            window.DarkModeManager.toggle();
            updateToggleButtonUI(this);
        });
    }
});

// Helper to update toggle button UI
function updateToggleButtonUI(button) {
    const isDarkMode = window.DarkModeManager.getPreference();
    
    if (button.querySelector('i')) {
        // If button contains an icon element
        const icon = button.querySelector('i');
        if (isDarkMode) {
            icon.className = icon.className.replace(/bi-moon|bi-sun/g, 'bi-sun');
        } else {
            icon.className = icon.className.replace(/bi-moon|bi-sun/g, 'bi-moon');
        }
    } else {
        // Direct icon class on button
        if (isDarkMode) {
            button.innerHTML = '<i class="bi bi-sun"></i>';
        } else {
            button.innerHTML = '<i class="bi bi-moon"></i>';
        }
    }
}
