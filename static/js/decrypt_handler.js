document.addEventListener('DOMContentLoaded', function() {
    console.log("Decrypt handler script loaded!");
    
    // Get modal elements
    const decryptModal = document.getElementById('decryptModal');
    const decryptForm = document.getElementById('decrypt-form');
    const submitBtn = document.getElementById('decrypt-submit-btn');
    const loadingIndicator = document.getElementById('loading-indicator');
    const resultContainer = document.getElementById('decryption-result');
    const decryptedMessageElem = document.getElementById('decrypted-message');
    const copyBtn = document.getElementById('copy-message');
    const decryptAnotherBtn = document.getElementById('decrypt-another');
    
    // Only proceed if we have the necessary elements
    if (!decryptForm) {
        console.error("Decrypt form not found!");
        return;
    }
    
    // Handle submission via the decrypt button
    if (submitBtn) {
        submitBtn.addEventListener('click', function() {
            handleDecryptSubmission();
        });
    }
    
    // Handle submission via the form itself (if user presses enter)
    if (decryptForm) {
        decryptForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleDecryptSubmission();
        });
    }
    
    function handleDecryptSubmission() {
        // Fix: Add debugging
        console.log("Starting decrypt submission process");
        
        // Hide form, show loading
        document.getElementById('decrypt-form-container').style.display = 'none';
        loadingIndicator.style.display = 'block';
        submitBtn.style.display = 'none';
        resultContainer.style.display = 'none';
        
        // Create form data
        const formData = new FormData(decryptForm);
        
        // Debug form data
        console.log("Form data entries:");
        for (let [key, value] of formData.entries()) {
            console.log(key, value instanceof File ? `File: ${value.name}` : value);
        }
        
        // Determine if we're decrypting a stored image or uploaded file
        const imageId = formData.get('image_id');
        let url = imageId ? '/api/decrypt_saved_image' : '/decrypt';
        console.log(`Using decrypt endpoint: ${url}, Image ID: ${imageId}`);
        
        // Fix: Get a valid CSRF token
        const csrfToken = getCSRFToken();
        console.log("CSRF Token retrieved:", csrfToken ? "Yes" : "No");
        
        // Send AJAX request
        fetch(url, {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRFToken': csrfToken
            }
        })
        .then(response => {
            console.log("Server responded with status:", response.status);
            if (!response.ok) {
                throw new Error(`Server responded with status ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log("Received data from server:", data);
            loadingIndicator.style.display = 'none';
            
            if (data.success) {
                // Display decrypted message
                if (data.decrypted_message) {
                    decryptedMessageElem.value = data.decrypted_message;
                    resultContainer.style.display = 'block';
                    
                    // Apply dark mode styling if needed
                    applyDarkModeIfNeeded();
                } else {
                    throw new Error('No message found in response');
                }
            } else {
                throw new Error(data.message || 'Failed to decrypt message');
            }
        })
        .catch(error => {
            console.error('Decrypt error:', error);
            loadingIndicator.style.display = 'none';
            
            // Show error message
            if (typeof Swal !== 'undefined') {
                Swal.fire({
                    icon: 'error',
                    title: 'Decryption Failed',
                    text: error.message || 'Failed to decrypt message. Please check your password and try again.',
                    confirmButtonColor: '#4dabde'
                }).then(() => {
                    // Reset the form state
                    document.getElementById('decrypt-form-container').style.display = 'block';
                    submitBtn.style.display = 'inline-block';
                });
            } else {
                alert('Decryption failed: ' + (error.message || 'Unknown error'));
                document.getElementById('decrypt-form-container').style.display = 'block';
                submitBtn.style.display = 'inline-block';
            }
        });
    }
    
    // Fix: Improved CSRF token retrieval
    function getCSRFToken() {
        // First try meta tag
        const metaToken = document.querySelector('meta[name="csrf-token"]');
        if (metaToken) {
            return metaToken.getAttribute('content');
        }
        
        // Then try hidden input field in form
        const tokenInput = decryptForm.querySelector('input[name="csrf_token"]');
        if (tokenInput) {
            return tokenInput.value;
        }
        
        // Fall back to any csrf_token input on the page
        const anyTokenInput = document.querySelector('input[name="csrf_token"]');
        if (anyTokenInput) {
            return anyTokenInput.value;
        }
        
        console.error("CSRF token not found");
        return '';
    }
    
    // Handle copy button
    if (copyBtn && decryptedMessageElem) {
        copyBtn.addEventListener('click', function() {
            decryptedMessageElem.select();
            document.execCommand('copy');
            
            const originalHTML = this.innerHTML;
            this.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';
            this.classList.add('btn-success');
            this.classList.remove('btn-outline-secondary');
            
            setTimeout(() => {
                this.innerHTML = originalHTML;
                this.classList.remove('btn-success');
                this.classList.add('btn-outline-secondary');
            }, 2000);
        });
    }
    
    // Handle decrypt another button
    if (decryptAnotherBtn) {
        decryptAnotherBtn.addEventListener('click', function() {
            resultContainer.style.display = 'none';
            document.getElementById('decrypt-form-container').style.display = 'block';
            submitBtn.style.display = 'inline-block';
            decryptForm.reset();
            
            // Show file upload field again
            document.getElementById('image-upload-container').style.display = 'block';
        });
    }
    
    // Apply dark mode styling to modal content
    function applyDarkModeIfNeeded() {
        const isDarkMode = document.documentElement.getAttribute('data-bs-theme') === 'dark';
        
        if (isDarkMode) {
            // Fix modal backdrop if present
            document.querySelectorAll('.modal-backdrop').forEach(el => {
                el.style.backgroundColor = 'rgba(0, 0, 0, 0.4)';
                el.style.opacity = '0.4';
            });
            
            // Style decrypt containers
            document.querySelectorAll('#decryption-result, #resultCard').forEach(el => {
                el.style.backgroundColor = 'var(--dark-bg-secondary)';
                el.style.color = 'var(--dark-text-primary)';
                el.style.borderColor = 'var(--dark-border-color)';
            });
            
            // Style textareas and message containers
            document.querySelectorAll('#decrypted-message, textarea.form-control[readonly]').forEach(el => {
                el.style.backgroundColor = 'var(--dark-bg-tertiary)';
                el.style.color = 'var(--dark-text-primary)';
                el.style.borderColor = 'var(--dark-border-color)';
            });
            
            // Fix modal itself
            document.querySelectorAll('.modal-content').forEach(el => {
                el.style.backgroundColor = 'var(--dark-bg-secondary)';
                el.style.color = 'var(--dark-text-primary)';
            });
        }
    }
    
    // Apply dark mode styling when needed
    if (decryptModal) {
        decryptModal.addEventListener('shown.bs.modal', applyDarkModeIfNeeded);
    }
    
    document.addEventListener('userDarkModeChange', applyDarkModeIfNeeded);
    
    // Initial application of dark mode if necessary
    if (document.documentElement.getAttribute('data-bs-theme') === 'dark') {
        applyDarkModeIfNeeded();
    }
});
