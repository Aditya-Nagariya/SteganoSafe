/**
 * User Dark Mode Manager
 * Handles dark mode functionality for user-facing pages
 * Completely separate from admin dark mode
 */

const UserDarkMode = {
    // Key for localStorage
    STORAGE_KEY: 'stegano_user_dark_mode',
    
    // Initialize dark mode
    init() {
        console.log('Initializing user dark mode');
        
        // Check if dark mode should be enabled
        const darkModeEnabled = this.shouldEnableDarkMode();
        
        // Apply initial state
        this.setDarkMode(darkModeEnabled, false);
        
        // Set up toggle button event listener
        this.setupToggleButton();
        
        // Set up system preference change listener
        this.setupSystemPreferenceListener();
        
        return this;
    },
    
    // Should dark mode be enabled based on stored preference or system preference
    shouldEnableDarkMode() {
        // Check localStorage first
        const storedPreference = localStorage.getItem(this.STORAGE_KEY);
        if (storedPreference !== null) {
            return storedPreference === 'true';
        }
        
        // Fall back to system preference
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    },
    
    // Set dark mode state
    setDarkMode(enable, savePreference = true) {
        // Set data attribute on html element
        document.documentElement.setAttribute('data-bs-theme', enable ? 'dark' : 'light');
        document.documentElement.classList.toggle('user-dark-mode', enable);
        document.body.classList.toggle('user-dark-mode', enable);
        
        // Save preference if requested
        if (savePreference) {
            localStorage.setItem(this.STORAGE_KEY, enable);
        }
        
        // Update toggle button if it exists
        const toggleButton = document.getElementById('userDarkModeToggle');
        if (toggleButton) {
            const icon = toggleButton.querySelector('i');
            const label = toggleButton.querySelector('span');
            
            if (icon) {
                icon.className = enable ? 'bi bi-moon-stars-fill' : 'bi bi-sun-fill';
            }
            
            if (label) {
                label.textContent = enable ? 'Dark' : 'Light';
            }
        }
        
        // Dispatch event for other scripts
        document.dispatchEvent(new CustomEvent('userDarkModeChange', { 
            detail: { darkMode: enable }
        }));
        
        console.log('User dark mode:', enable ? 'enabled' : 'disabled');
    },
    
    // Toggle dark mode
    toggle() {
        const isDarkMode = document.documentElement.getAttribute('data-bs-theme') === 'dark';
        this.setDarkMode(!isDarkMode);
    },
    
    // Set up toggle button
    setupToggleButton() {
        const toggleButton = document.getElementById('userDarkModeToggle');
        if (toggleButton) {
            toggleButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggle();
            });
        }
    },
    
    // Listen for system preference changes
    setupSystemPreferenceListener() {
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            
            if (mediaQuery.addEventListener) {
                mediaQuery.addEventListener('change', (e) => {
                    // Only change if user hasn't set a preference
                    if (localStorage.getItem(this.STORAGE_KEY) === null) {
                        this.setDarkMode(e.matches, false);
                    }
                });
            }
        }
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    UserDarkMode.init();
});

// Export for other scripts
window.UserDarkMode = UserDarkMode;
