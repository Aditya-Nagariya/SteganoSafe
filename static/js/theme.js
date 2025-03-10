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
    if (detectDarkMode()) {
        document.documentElement.classList.add('dark-mode');
        document.body.classList.add('dark-mode');
        
        // Update meta theme color for dark mode
        if (metaThemeColor) {
            metaThemeColor.content = "#1a1d21"; // Dark mode color
        }
    }

    // Add subtle hover effects to cards
    document.querySelectorAll('.hover-card').forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
            this.style.boxShadow = '0 12px 24px rgba(0,0,0,0.12)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)';
        });
    });

    // Add ripple effect to buttons
    document.querySelectorAll('.btn').forEach(button => {
        button.addEventListener('click', function(e) {
            const ripple = document.createElement('div');
            ripple.className = 'ripple';
            ripple.style.left = `${e.offsetX}px`;
            ripple.style.top = `${e.offsetY}px`;
            
            this.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
    
    // Debug dark mode state
    console.log('Dark mode enabled:', document.body.classList.contains('dark-mode'));
    
    // Check if we're using dark-mode.js
    if (window.DarkModeManager) {
        console.log('DarkModeManager found');
        
        // Sync theme.js with DarkModeManager
        document.addEventListener('darkModeChange', function(e) {
            // Update meta theme color when dark mode changes
            if (metaThemeColor) {
                metaThemeColor.content = e.detail.darkMode ? "#1a1d21" : "#2c7da0";
            }
        });
    } else {
        console.log('DarkModeManager not found');
    }
    
    // Force apply dark mode styles to ensure they're applied
    if (document.body.classList.contains('dark-mode')) {
        applyDarkModeToAll();
    }
    
    // Function to recursively apply dark mode to all elements
    function applyDarkModeToAll() {
        // Apply to specific troublesome elements
        document.querySelectorAll('.card, .admin-card, .admin-content, .admin-sidebar, .dropdown-menu').forEach(el => {
            el.classList.add('dark-mode-element');
        });
        
        // Apply to wrapper elements that might be causing issues
        document.querySelectorAll('.admin-wrapper').forEach(el => {
            el.style.backgroundColor = '#1a1d21';
            el.style.color = '#e1e2f6';
        });
    }
});
