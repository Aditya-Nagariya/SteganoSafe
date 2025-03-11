/**
 * Modal Fix - EMERGENCY FIXED VERSION
 * - Ensures modals display correctly in both light and dark modes
 * - Maintains clickability of all dashboard elements
 * - Preserves proper layout spacing when modal is open
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap modals if needed
    if (typeof bootstrap !== 'undefined') {
        document.querySelectorAll('.modal').forEach(function(modalElement) {
            // Initialize modal if not already initialized
            if (!bootstrap.Modal.getInstance(modalElement)) {
                new bootstrap.Modal(modalElement);
            }
        });
    }
    
    // Apply dark mode styles to modals when theme changes
    document.addEventListener('userDarkModeChange', function(e) {
        const isDarkMode = e.detail.darkMode;
        
        // Safely update any open modals
        document.querySelectorAll('.modal.show').forEach(modal => {
            const content = modal.querySelector('.modal-content');
            if (content) {
                // Apply appropriate theme without disrupting functionality
                if (isDarkMode) {
                    content.style.backgroundColor = '#2a2a2a';
                    content.style.color = '#e1e1e1';
                    content.style.borderColor = 'rgba(255, 255, 255, 0.2)';
                } else {
                    content.style.backgroundColor = '#fff';
                    content.style.color = '#212529';
                    content.style.borderColor = 'rgba(0, 0, 0, 0.2)';
                }
            }
            
            // Update inputs and text areas
            modal.querySelectorAll('input, textarea, select').forEach(el => {
                if (isDarkMode) {
                    el.style.backgroundColor = '#333';
                    el.style.color = '#e1e1e1';
                    el.style.borderColor = 'rgba(255, 255, 255, 0.15)';
                } else {
                    el.style.backgroundColor = '';
                    el.style.color = '';
                    el.style.borderColor = '';
                }
            });
        });
    });
    
    // Fix for modal in dark mode without breaking interactions
    function applyDarkModeModalFix() {
        if (document.documentElement.getAttribute('data-bs-theme') === 'dark') {
            // Make sure content is visible in dark mode, but don't disrupt interactions
            document.querySelectorAll('#decryptModal .modal-content').forEach(el => {
                el.style.backgroundColor = '#2a2a2a';
                el.style.color = '#e1e1e1';
                el.style.borderColor = 'rgba(255, 255, 255, 0.2)';
                el.style.boxShadow = '0 8px 25px rgba(0, 0, 0, 0.8), 0 0 15px rgba(44, 125, 160, 0.5)';
            });
            
            // Style form controls but preserve interaction
            document.querySelectorAll('#decryptModal input, #decryptModal textarea, #decryptModal select').forEach(el => {
                el.style.backgroundColor = '#333';
                el.style.color = '#e1e1e1';
                el.style.borderColor = 'rgba(255, 255, 255, 0.15)';
            });
            
            // Style decrypted message area
            document.querySelectorAll('#decrypted-message, #dashboard-decrypted-message').forEach(el => {
                el.style.backgroundColor = '#333';
                el.style.color = '#e1e1e1';
                el.style.borderColor = 'rgba(255, 255, 255, 0.15)';
            });
        }
    }
    
    // Apply the fix when modals are shown
    document.addEventListener('show.bs.modal', function() {
        setTimeout(applyDarkModeModalFix, 10);
        
        // NEW: Fix image grid spacing when modal opens
        setTimeout(fixImageGridSpacing, 20);
    });
    
    // Also apply on dark mode change
    document.addEventListener('userDarkModeChange', function() {
        setTimeout(applyDarkModeModalFix, 10);
    });
    
    // Apply immediately if needed
    setTimeout(applyDarkModeModalFix, 100);
    
    // Properly close modals when escape key is pressed
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            document.querySelectorAll('.modal.show').forEach(modal => {
                const modalInstance = bootstrap.Modal.getInstance(modal);
                if (modalInstance) {
                    modalInstance.hide();
                }
            });
        }
    });
    
    // NEW: Function to fix image grid spacing issues
    function fixImageGridSpacing() {
        // Target the image grid columns
        document.querySelectorAll('.col-md-4').forEach(col => {
            col.style.marginBottom = '1.5rem';
            col.style.paddingLeft = '0.75rem';
            col.style.paddingRight = '0.75rem';
        });
        
        // Fix card heights in the image grid
        document.querySelectorAll('.col-md-4 .card').forEach(card => {
            card.style.height = '100%';
            card.style.marginBottom = '0';
            card.style.display = 'flex';
            card.style.flexDirection = 'column';
        });
        
        // Ensure rows display correctly
        document.querySelectorAll('.row').forEach(row => {
            row.style.display = 'flex';
            row.style.flexWrap = 'wrap';
            row.style.marginRight = '-0.75rem';
            row.style.marginLeft = '-0.75rem';
        });
    }
});
