/**
 * Fixes dropdown issues and ensures options are correctly displayed
 */
document.addEventListener('DOMContentLoaded', function() {
    // Fix for encryption method dropdown
    const encryptionMethodDropdown = document.getElementById('encryption_method');
    const decryptMethodDropdown = document.getElementById('decrypt-method');
    
    // Function to ensure dropdown is properly initialized
    function initializeDropdown(dropdown) {
        if (!dropdown) return;
        
        // Force refresh the dropdown
        const currentValue = dropdown.value;
        
        // Create a new event to trigger any listeners
        const event = new Event('change', { bubbles: true });
        dropdown.dispatchEvent(event);
        
        // Add click listener to ensure dropdown expands
        dropdown.addEventListener('click', function(e) {
            // Prevent immediate closing
            e.stopPropagation();
            
            // Make sure options are visible by toggling the 'show' class
            const dropdownMenu = this.nextElementSibling;
            if (dropdownMenu && dropdownMenu.classList.contains('dropdown-menu')) {
                dropdownMenu.classList.toggle('show');
            }
        });
    }
    
    // Initialize both dropdowns
    initializeDropdown(encryptionMethodDropdown);
    initializeDropdown(decryptMethodDropdown);
    
    // Add this CSS fix for dropdowns
    const style = document.createElement('style');
    style.textContent = `
        .dropdown-menu.show {
            display: block !important;
            opacity: 1 !important;
            visibility: visible !important;
            transform: none !important;
        }
        select.form-select {
            appearance: auto !important; /* Override any CSS that might hide the dropdown arrow */
        }
    `;
    document.head.appendChild(style);
    
    // For Bootstrap dropdowns, ensure they show properly
    const dropdownToggles = document.querySelectorAll('.dropdown-toggle');
    dropdownToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const menu = this.nextElementSibling;
            if (menu && menu.classList.contains('dropdown-menu')) {
                menu.classList.toggle('show');
            }
        });
    });
    
    // Close dropdowns when clicking outside
    document.addEventListener('click', function(e) {
        const dropdownMenus = document.querySelectorAll('.dropdown-menu.show');
        dropdownMenus.forEach(menu => {
            if (!menu.contains(e.target)) {
                menu.classList.remove('show');
            }
        });
    });
});
