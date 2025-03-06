/**
 * Dashboard functionality for SteganoSafe
 */
document.addEventListener('DOMContentLoaded', function() {
    // Update badge tooltips for encryption methods
    const methodBadges = document.querySelectorAll('.badge');
    methodBadges.forEach(badge => {
        const method = badge.textContent.trim();
        switch(method) {
            case 'LSB':
                badge.title = 'Least Significant Bit - Fast with decent capacity';
                badge.classList.add('bg-success');
                break;
            case 'PVD':
                badge.title = 'Pixel Value Differencing - Better security than LSB';
                badge.classList.add('bg-primary');
                break;
            case 'DCT':
                badge.title = 'Discrete Cosine Transform - Resistant to compression';
                badge.classList.add('bg-warning', 'text-dark');
                break;
            case 'DWT':
                badge.title = 'Discrete Wavelet Transform - Advanced steganography';
                badge.classList.add('bg-danger');
                break;
            default:
                badge.title = 'Encryption method';
        }
    });

    // Add method to decrypt buttons
    const decryptButtons = document.querySelectorAll('.decrypt-btn');
    decryptButtons.forEach(button => {
        // Find the closest card containing this button
        const card = button.closest('.card');
        if (card) {
            // Find the method badge in this card
            const methodBadge = card.querySelector('.badge');
            if (methodBadge) {
                // Set the method as a data attribute on the button
                button.setAttribute('data-encryption-method', methodBadge.textContent.trim());
            }
        }
    });

    const decryptModal = new bootstrap.Modal(document.getElementById('decryptModal'));
    const decryptForm = document.getElementById('decrypt-form');
    
    // Add click handler to each button
    decryptButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Get the image ID from data attribute
            const imageId = this.getAttribute('data-image-id');
            
            // Reset the form before showing the modal
            decryptForm.reset();
            
            // Clear previous results and errors
            document.getElementById('decrypt-error').classList.add('d-none');
            document.getElementById('decrypt-result').classList.add('d-none');
            document.getElementById('decrypted-message').value = '';
            document.getElementById('decrypt-btn').classList.remove('d-none');
            document.getElementById('decrypt-spinner').classList.add('d-none');
            
            // Set the image ID in a hidden field
            document.getElementById('decrypt-image-id').value = imageId;
            
            // Show the modal
            decryptModal.show();
        });
    });
    
    // Add event listener to modal hidden event to reset form
    const modalElement = document.getElementById('decryptModal');
    modalElement.addEventListener('hidden.bs.modal', function() {
        decryptForm.reset();
        document.getElementById('decrypt-error').classList.add('d-none');
        document.getElementById('decrypt-result').classList.add('d-none');
    });
    
    // Add retry logic for decryption
    if (decryptForm) {
        decryptForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Show loading spinner
            document.getElementById('decrypt-btn').classList.add('d-none');
            document.getElementById('decrypt-spinner').classList.remove('d-none');
            document.getElementById('decrypt-result').classList.add('d-none');
            document.getElementById('decrypt-error').classList.add('d-none');
            
            // Get password from form
            const password = document.getElementById('decrypt-password').value;
            const imageId = document.getElementById('decrypt-image-id').value;
            const encryptionMethod = document.getElementById('decrypt-method').value;
            
            // Create form data
            const formData = new FormData();
            formData.append('password', password);
            formData.append('image_id', imageId);
            formData.append('encryption_method', encryptionMethod);
            
            // Add CSRF token if present
            const csrfTokenField = document.querySelector('input[name=csrf_token]');
            if (csrfTokenField) {
                formData.append('csrf_token', csrfTokenField.value);
            }
            
            console.log("Attempting to decrypt stored image...");
            
            // First try the primary endpoint
            fetch('/decrypt-stored', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    console.warn(`Primary endpoint failed with status ${response.status}, trying fallback...`);
                    // Try the API endpoint instead
                    return fetch('/api/decrypt_saved_image', {
                        method: 'POST',
                        body: formData
                    });
                }
                return response;
            })
            .then(response => response.json())
            .then(data => {
                // Hide spinner
                document.getElementById('decrypt-spinner').classList.add('d-none');
                document.getElementById('decrypt-btn').classList.remove('d-none');
                
                if (data.success) {
                    // Show result
                    document.getElementById('decrypted-message').value = data.decrypted_message || "Message successfully decrypted!";
                    document.getElementById('decrypt-result').classList.remove('d-none');
                } else {
                    // Show error
                    document.getElementById('decrypt-error-message').textContent = data.message || 'Decryption failed. Please check your password and try again.';
                    document.getElementById('decrypt-error').classList.remove('d-none');
                }
            })
            .catch(error => {
                console.error('Error during decryption:', error);
                document.getElementById('decrypt-spinner').classList.add('d-none');
                document.getElementById('decrypt-btn').classList.remove('d-none');
                document.getElementById('decrypt-error-message').textContent = 'An error occurred during decryption. Please try again.';
                document.getElementById('decrypt-error').classList.remove('d-none');
            });
        });
    }
    
    // Add copy to clipboard functionality if needed
    const copyButton = document.getElementById('copy-decrypted');
    if (copyButton) {
        copyButton.addEventListener('click', function() {
            const messageText = document.getElementById('decrypted-message').value;
            navigator.clipboard.writeText(messageText)
                .then(() => {
                    // Show success indicator
                    const originalText = copyButton.innerHTML;
                    copyButton.innerHTML = '<i class="bi bi-check"></i> Copied!';
                    setTimeout(() => {
                        copyButton.innerHTML = originalText;
                    }, 2000);
                })
                .catch(err => {
                    console.error('Failed to copy text: ', err);
                });
        });
    }
});

/**
 * Dashboard main functionality
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard JS loaded');
    
    // Global modal backdrop fix
    function fixModalBackdrop() {
        // Check for orphaned backdrops
        const hasOpenModals = document.querySelector('.modal.show') !== null;
        const hasBackdrops = document.querySelector('.modal-backdrop') !== null;
        
        if (!hasOpenModals && hasBackdrops) {
            console.log('Cleaning up orphaned modal backdrops');
            // Remove all backdrops
            document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
            
            // Fix body
            document.body.classList.remove('modal-open');
            document.body.style.paddingRight = '';
            document.body.style.overflow = '';
        }
    }
    
    // Run on page load
    fixModalBackdrop();
    
    // Run periodically 
    setInterval(fixModalBackdrop, 2000);
    
    // Add handler for all modal close buttons
    document.querySelectorAll('[data-bs-dismiss="modal"]').forEach(button => {
        button.addEventListener('click', function() {
            // Run cleanup after animation completes
            setTimeout(fixModalBackdrop, 300);
        });
    });
    
    // Add handler for ESC key to also clean up backdrops
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            setTimeout(fixModalBackdrop, 300);
        }
    });
    
    // Patch Bootstrap's modal hide function to ensure proper cleanup
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        const originalHide = bootstrap.Modal.prototype.hide;
        bootstrap.Modal.prototype.hide = function() {
            originalHide.apply(this, arguments);
            setTimeout(fixModalBackdrop, 300);
        };
    }
});
