/**
 * SteganoSafe Theme Manager
 * Centralized theme management to handle dark/light mode
 */

// Create a self-executing function to avoid global scope pollution
(function() {
    // Create global ThemeManager object
    window.ThemeManager = {
        // Store theme state
        isDarkMode: false,
        
        // Initialize theme manager
        init: function() {
            console.log('ThemeManager: Initializing...');
            
            // Detect initial state (localStorage > cookies > system preference)
            this.isDarkMode = this.detectDarkMode();
            
            // Apply initial theme
            this.applyTheme(this.isDarkMode, true, false); // Apply without server sync on initial load
            
            // Set up synchronization with DarkModeManager if it exists
            if (window.DarkModeManager) {
                console.log('ThemeManager: DarkModeManager found, syncing...');
                document.addEventListener('darkModeChange', function(e) {
                    window.ThemeManager.applyTheme(e.detail.darkMode, false);
                });
            }
            
            // Initialize theme controls
            this.initControls();
            
            console.log('ThemeManager: Initialization complete. Dark mode:', this.isDarkMode);
            return this;
        },
        
        // Detect dark mode preference from various sources
        detectDarkMode: function() {
            // 1. Check localStorage (highest priority)
            const savedPreference = localStorage.getItem('admin_dark_mode_enabled');
            if (savedPreference === 'true') return true;
            if (savedPreference === 'false') return false;
            
            // 2. Check for cookie
            const darkModeCookie = document.cookie.split('; ')
                .find(row => row.startsWith('dark_mode='));
                
            if (darkModeCookie) {
                const cookieValue = darkModeCookie.split('=')[1];
                if (cookieValue === '1') return true;
                if (cookieValue === '0') return false;
            }
            
            // 3. Check body class (server-side rendered state)
            if (document.body.classList.contains('dark-mode')) return true;
            
            // 4. Check system preference (lowest priority)
            return window.matchMedia && 
                   window.matchMedia('(prefers-color-scheme: dark)').matches;
        },
        
        // Toggle dark mode on/off
        toggle: function() {
            console.log('ThemeManager: Toggling theme...');
            this.isDarkMode = !this.isDarkMode;
            this.applyTheme(this.isDarkMode);
        },
        
        // Set specific theme
        setDarkMode: function(enableDark) {
            if (this.isDarkMode !== enableDark) {
                this.isDarkMode = enableDark;
                this.applyTheme(enableDark);
            }
        },
        
        // Apply theme to the page
        applyTheme: function(isDark, savePreference = true, syncWithServer = true) {
            console.log('ThemeManager: Applying theme, dark mode:', isDark);
            
            // 1. Update DOM classes
            const htmlElement = document.documentElement;
            const bodyElement = document.body;
            
            if (isDark) {
                htmlElement.classList.add('dark-mode');
                bodyElement.classList.add('dark-mode');
            } else {
                htmlElement.classList.remove('dark-mode');
                bodyElement.classList.remove('dark-mode');
            }
            
            // 2. Update meta theme-color
            const metaThemeColor = document.querySelector('meta[name="theme-color"]');
            if (metaThemeColor) {
                metaThemeColor.content = isDark ? "#1a1d21" : "#2c7da0";
            }
            
            // 3. Save preference (if requested)
            if (savePreference) {
                localStorage.setItem('admin_dark_mode_enabled', isDark);
                document.cookie = `dark_mode=${isDark ? '1' : '0'}; path=/; max-age=31536000; SameSite=Strict`;
                
                // Also update DarkModeManager if it exists
                if (window.DarkModeManager && typeof window.DarkModeManager.setPreference === 'function') {
                    window.DarkModeManager.setPreference(isDark);
                }
            }
            
            // 4. Sync with server (to maintain state in Flask session)
            if (syncWithServer) {
                this.syncWithServer(isDark);
            }
            
            // 5. Dispatch theme change event
            const event = new CustomEvent('themeChange', { 
                detail: { darkMode: isDark } 
            });
            document.dispatchEvent(event);
            
            // 6. Update all theme controls
            this.updateControls(isDark);
        },
        
        // Sync dark mode state with server
        syncWithServer: function(isDark) {
            // Get CSRF token if available
            let headers = { 'Content-Type': 'application/json' };
            const csrfToken = this.getCsrfToken();
            if (csrfToken) {
                headers['X-CSRF-Token'] = csrfToken;
            }
            
            // Send request to update session state
            fetch('/update_theme_preference', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ dark_mode: isDark }),
                credentials: 'same-origin' // Important for session cookies
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to update theme preference on server');
                }
                return response.json();
            })
            .then(data => {
                console.log('Theme preference updated on server:', data);
            })
            .catch(error => {
                // Just log errors - don't break the UI if server sync fails
                console.error('Error syncing theme with server:', error);
            });
        },
        
        // Helper to get CSRF token
        getCsrfToken: function() {
            const metaToken = document.querySelector('meta[name="csrf-token"]');
            if (metaToken) {
                return metaToken.getAttribute('content');
            }
            
            const inputToken = document.querySelector('input[name="csrf_token"]');
            if (inputToken) {
                return inputToken.value;
            }
            
            return null;
        },
        
        // Initialize theme controls
        initControls: function() {
            // Find toggle button and switch
            const themeToggle = document.getElementById('themeToggle');
            const darkModeSwitch = document.getElementById('darkModeSwitch');
            
            // Set up theme toggle button
            if (themeToggle) {
                this.updateThemeToggleIcon(themeToggle, this.isDarkMode);
                
                themeToggle.addEventListener('click', function(e) {
                    e.preventDefault();
                    window.ThemeManager.toggle();
                });
            }
            
            // Set up theme switch
            if (darkModeSwitch) {
                darkModeSwitch.checked = this.isDarkMode;
                
                darkModeSwitch.addEventListener('change', function() {
                    window.ThemeManager.setDarkMode(this.checked);
                });
            }
        },
        
        // Update all theme controls
        updateControls: function(isDarkMode) {
            const themeToggle = document.getElementById('themeToggle');
            const darkModeSwitch = document.getElementById('darkModeSwitch');
            
            // Update toggle button icon
            if (themeToggle) {
                this.updateThemeToggleIcon(themeToggle, isDarkMode);
            }
            
            // Update switch state
            if (darkModeSwitch) {
                darkModeSwitch.checked = isDarkMode;
            }
        },
        
        // Update theme toggle button icon
        updateThemeToggleIcon: function(button, isDarkMode) {
            button.innerHTML = isDarkMode ? 
                '<i class="bi bi-sun"></i>' : 
                '<i class="bi bi-moon"></i>';
        }
    };
    
    // Initialize theme manager when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        window.ThemeManager.init();
    });
})();
