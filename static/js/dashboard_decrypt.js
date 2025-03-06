document.addEventListener('DOMContentLoaded', function() {
    // Handle dashboard direct decrypt form
    const dashboardDecryptForm = document.getElementById('dashboard-decrypt-form');
    
    if (dashboardDecryptForm) {
        const loadingIndicator = document.getElementById('dashboard-loading-indicator');
        const decryptionResult = document.getElementById('dashboard-decryption-result');
        const decryptedMessageArea = document.getElementById('dashboard-decrypted-message');
        
        dashboardDecryptForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form data
            const formData = new FormData(dashboardDecryptForm);
            
            // Show loading indicator
            dashboardDecryptForm.style.display = 'none';
            loadingIndicator.style.display = 'block';
            
            // Submit form
            fetch('/decrypt', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                loadingIndicator.style.display = 'none';
                
                if (data.success) {
                    // Show decryption result
                    decryptionResult.style.display = 'block';
                    decryptedMessageArea.value = data.decrypted_message;
                } else {
                    // Show detailed error and reset form
                    const errorMessage = data.message || 'Decryption failed';
                    
                    // Create a bootstrap alert for better visibility
                    const alertDiv = document.createElement('div');
                    alertDiv.className = 'alert alert-danger alert-dismissible fade show';
                    alertDiv.innerHTML = `
                        <strong>Decryption Failed:</strong> ${errorMessage}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    `;
                    
                    // Insert the alert before the form
                    dashboardDecryptForm.parentNode.insertBefore(alertDiv, dashboardDecryptForm);
                    
                    // Show the form again
                    dashboardDecryptForm.style.display = 'block';
                    
                    // Automatically remove the alert after 10 seconds
                    setTimeout(() => {
                        alertDiv.remove();
                    }, 10000);
                }
            })
            .catch(error => {
                loadingIndicator.style.display = 'none';
                dashboardDecryptForm.style.display = 'block';
                
                // Create error alert with more details
                const alertDiv = document.createElement('div');
                alertDiv.className = 'alert alert-danger';
                alertDiv.innerHTML = `
                    <strong>Error:</strong> An unexpected error occurred during decryption. 
                    Please try again or contact support if the issue persists.
                `;
                
                // Insert the alert before the form
                dashboardDecryptForm.parentNode.insertBefore(alertDiv, dashboardDecryptForm);
                
                console.error('Decryption error:', error);
            });
        });
        
        // Handle "Decrypt Another" button click
        const decryptAnotherBtn = document.getElementById('decrypt-another');
        if (decryptAnotherBtn) {
            decryptAnotherBtn.addEventListener('click', function() {
                decryptionResult.style.display = 'none';
                dashboardDecryptForm.reset();
                dashboardDecryptForm.style.display = 'block';
                
                // Remove any existing alerts
                const existingAlerts = document.querySelectorAll('.alert');
                existingAlerts.forEach(alert => alert.remove());
            });
        }
        
        // Handle Copy button
        const copyBtn = document.getElementById('dashboard-copy-message');
        if (copyBtn) {
            copyBtn.addEventListener('click', function() {
                decryptedMessageArea.select();
                
                // Use modern clipboard API
                try {
                    navigator.clipboard.writeText(decryptedMessageArea.value)
                    .then(() => {
                        // Show success feedback
                        const originalText = copyBtn.textContent;
                        copyBtn.textContent = '✓ Copied!';
                        setTimeout(() => {
                            copyBtn.textContent = originalText;
                        }, 1500);
                    });
                } catch (err) {
                    // Fall back to the old method
                    document.execCommand('copy');
                    const originalText = copyBtn.textContent;
                    copyBtn.textContent = '✓ Copied!';
                    setTimeout(() => {
                        copyBtn.textContent = originalText;
                    }, 1500);
                }
            });
        }
    }
    
    // Handle decrypt modal for saved images
    const decryptModal = document.getElementById('decryptModal');
    if (decryptModal) {
        // Add this code for proper modal cleanup
        decryptModal.addEventListener('hidden.bs.modal', function() {
            // Ensure the backdrop is removed
            const backdrop = document.querySelector('.modal-backdrop');
            if (backdrop) {
                backdrop.remove();
            }
            
            // Ensure body classes are cleaned up
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
            
            // Reset form fields
            const form = document.getElementById('decrypt-form');
            if (form) form.reset();
            
            // Hide error and result sections
            const errorSection = document.getElementById('decrypt-error');
            if (errorSection) errorSection.classList.add('d-none');
            
            const resultSection = document.getElementById('decrypt-result');
            if (resultSection) resultSection.classList.add('d-none');
        });
        
        const decryptButtons = document.querySelectorAll('.decrypt-btn');
        const decryptForm = document.getElementById('decrypt-form');
        const decryptImageId = document.getElementById('decrypt-image-id');
        const decryptMethod = document.getElementById('decrypt-method');
        const decryptBtn = document.getElementById('decrypt-btn');
        const decryptSpinner = document.getElementById('decrypt-spinner');
        const decryptResult = document.getElementById('decrypt-result');
        const decryptedMessage = document.getElementById('decrypted-message');
        const decryptError = document.getElementById('decrypt-error');
        const decryptErrorMessage = document.getElementById('decrypt-error-message');
        
        // Set up modal trigger buttons
        decryptButtons.forEach(button => {
            button.addEventListener('click', function() {
                const imageId = this.getAttribute('data-image-id');
                const encryptionMethod = this.getAttribute('data-encryption-method') || 'LSB';
                
                // Reset form and results
                decryptForm.reset();
                decryptResult.classList.add('d-none');
                decryptError.classList.add('d-none');
                decryptImageId.value = imageId;
                
                // Set encryption method if available
                if (decryptMethod && decryptMethod.querySelector(`option[value="${encryptionMethod}"]`)) {
                    decryptMethod.value = encryptionMethod;
                }
                
                // Show the modal
                const modal = new bootstrap.Modal(decryptModal);
                modal.show();
            });
        });
        
        // Handle decrypt form submission
        if (decryptForm) {
            decryptForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                // Hide any previous results/errors
                decryptResult.classList.add('d-none');
                decryptError.classList.add('d-none');
                
                // Show loading spinner
                decryptBtn.classList.add('d-none');
                decryptSpinner.classList.remove('d-none');
                
                // Get form data
                const formData = new FormData(decryptForm);
                
                // Add the image ID and chosen method
                formData.append('image_id', decryptImageId.value);
                formData.append('encryption_method', decryptMethod.value);
                
                // Submit via AJAX
                fetch('/api/decrypt_saved_image', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    // Hide spinner
                    decryptBtn.classList.remove('d-none');
                    decryptSpinner.classList.add('d-none');
                    
                    if (data.success) {
                        // Show decryption result
                        decryptedMessage.value = data.decrypted_message;
                        decryptResult.classList.remove('d-none');
                    } else {
                        // Show error
                        decryptErrorMessage.textContent = data.message || 'Decryption failed';
                        decryptError.classList.remove('d-none');
                    }
                })
                .catch(error => {
                    // Hide spinner, show button
                    decryptBtn.classList.remove('d-none');
                    decryptSpinner.classList.add('d-none');
                    
                    // Show error
                    decryptErrorMessage.textContent = 'An error occurred during decryption';
                    decryptError.classList.remove('d-none');
                    console.error('Decryption error:', error);
                });
            });
        }
    }
    
    // Add global cleanup function that runs periodically
    function cleanupModalBackdrops() {
        // Check if any modals are open
        const openModals = document.querySelector('.modal.show');
        if (!openModals) {
            // If no modal is open but backdrop exists, remove it
            const backdrops = document.querySelectorAll('.modal-backdrop');
            if (backdrops.length > 0) {
                backdrops.forEach(backdrop => {
                    backdrop.remove();
                });
                // Also cleanup body
                document.body.classList.remove('modal-open');
                document.body.style.overflow = '';
                document.body.style.paddingRight = '';
            }
        }
    }

    // Run cleanup every few seconds just in case
    setInterval(cleanupModalBackdrops, 3000);
    
    // Handle manual close buttons
    const closeButtons = document.querySelectorAll('[data-bs-dismiss="modal"]');
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Manually trigger backdrop cleanup after a short delay
            setTimeout(cleanupModalBackdrops, 100);
        });
    });
});
