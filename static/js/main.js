document.addEventListener('DOMContentLoaded', function () {
    // Generalized form handling function
    function handleFormSubmit(form, successCallback) {
        if (!form) return;
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            const formData = new FormData(this);

            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

            fetch(this.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRF-Token': csrfToken
                }
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        successCallback(data);
                    } else {
                        throw new Error(data.message || 'Unexpected Error');
                    }
                })
                .catch(error => {
                    Swal.fire({
                        icon: 'error',
                        title: 'Error',
                        text: error.message || 'An unexpected error occurred.'
                    });
                });

        });
    }

    // Success callbacks for specific forms
    function handleEncryptionSuccess(data) {
        Swal.fire({
            icon: 'success',
            title: 'Success',
            text: data.message
        }).then(() => {
            if (data.download_url) {
                window.location.href = data.download_url;
            }
            window.location.reload();
        });
    }

    function handleDecryptionSuccess(data) {
        const decryptResult = document.getElementById('decryptResult');
        const decryptedMessage = document.getElementById('decryptedMessage');
        if (decryptResult && decryptedMessage) {
            decryptedMessage.textContent = data.message;
            decryptResult.classList.remove('d-none');
            decryptResult.scrollIntoView({ behavior: 'smooth' });
        }
    }

    function handleRedirectSuccess(data) {
        window.location.href = data.redirect;
    }

    // Attach handlers to forms
    handleFormSubmit(document.getElementById('encryptForm'), handleEncryptionSuccess);
    handleFormSubmit(document.getElementById('decryptForm'), handleDecryptionSuccess);
    handleFormSubmit(document.querySelector('form[action*="login"]'), handleRedirectSuccess);
    handleFormSubmit(document.querySelector('form[action*="register"]'), function (data) {
        Swal.fire({
            icon: 'success',
            title: 'Success',
            text: 'Registration successful!'
        }).then(() => {
            window.location.href = data.redirect;
        });
    });

    // File input validation
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.addEventListener('change', function () {
            const file = this.files[0];
            const maxSize = 16 * 1024 * 1024; // 16MB
            if (file && file.size > maxSize) {
                this.value = '';
                Swal.fire({
                    icon: 'error',
                    title: 'File Too Large',
                    text: 'Please select an image under 16MB.'
                });
            }
        });
    });

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Auto-dismiss alerts after 5 seconds
    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});

// Enhance form submission handler for encryption
function setupEncryptionForm() {
    const encryptForm = document.getElementById('encrypt-form');
    if (!encryptForm) return;

    encryptForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Show loading indicator
        const submitBtn = encryptForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
        submitBtn.disabled = true;
        
        // Get form data
        const formData = new FormData(encryptForm);
        
        // Validate inputs
        const imageFile = formData.get('image');
        const password = formData.get('password');
        const message = formData.get('message');
        
        if (!imageFile || imageFile.size === 0) {
            showAlert('Please select an image file', 'danger');
            resetButton();
            return;
        }
        
        if (!password) {
            showAlert('Please enter an encryption password', 'danger');
            resetButton();
            return;
        }
        
        if (!message) {
            showAlert('Please enter a message to hide', 'danger');
            resetButton();
            return;
        }
        
        // Basic image validation
        if (!imageFile.type.startsWith('image/')) {
            showAlert('Please select a valid image file (JPEG, PNG, etc.)', 'danger');
            resetButton();
            return;
        }
        
        // File size validation (max 5MB)
        if (imageFile.size > 5 * 1024 * 1024) {
            showAlert('Image file too large. Maximum size is 5MB', 'danger');
            resetButton();
            return;
        }
        
        try {
            // Get CSRF token from meta tag
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            
            // Send request
            const response = await fetch('/encrypt', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRF-Token': csrfToken
                }
            });
            
            const result = await response.json();
            
            if (result.success) {
                showAlert(result.message || 'Encryption successful!', 'success');
                setTimeout(() => {
                    window.location.href = result.redirect || '/dashboard';
                }, 1500);
            } else {
                showAlert(result.message || 'Encryption failed. Please try again.', 'danger');
                resetButton();
            }
        } catch (error) {
            console.error('Encryption error:', error);
            showAlert('Error processing request. Please try again.', 'danger');
            resetButton();
        }
        
        function resetButton() {
            submitBtn.innerHTML = originalBtnText;
            submitBtn.disabled = false;
        }
        
        function showAlert(message, type) {
            const alertBox = document.createElement('div');
            alertBox.className = `alert alert-${type} alert-dismissible fade show`;
            alertBox.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;
            
            const container = document.querySelector('.container');
            container.insertBefore(alertBox, container.firstChild);
            
            // Auto dismiss after 5 seconds
            setTimeout(() => {
                alertBox.classList.remove('show');
                setTimeout(() => alertBox.remove(), 300);
            }, 5000);
        }
    });
}

// Add window.onload handler to initialize all functions
window.addEventListener('DOMContentLoaded', () => {
    setupEncryptionForm();
    // Add other initialization functions here
});

/**
 * Main JavaScript utilities for SteganoSafe
 */

// Global AJAX error handler for SweetAlert2
window.addEventListener('DOMContentLoaded', function() {
    // Check if SweetAlert2 is loaded
    if (typeof Swal !== 'undefined') {
        // Add global error handler for fetch
        const originalFetch = window.fetch;
        window.fetch = function() {
            return originalFetch.apply(this, arguments)
                .catch(error => {
                    console.error('Fetch error:', error);
                    // Show error message
                    Swal.fire({
                        icon: 'error',
                        title: 'Connection Error',
                        text: 'Failed to connect to the server. Please check your internet connection.',
                        confirmButtonColor: '#2c7da0'
                    });
                    throw error; 
                });
        };
    }
    
    // Log that JS is loaded for debugging
    console.log('SteganoSafe JS utilities loaded');
});

// Safe access to CSRF token
function getCsrfToken() {
    // Try to get from meta tag first (best practice)
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    if (metaToken) {
        return metaToken.getAttribute('content');
    }
    
    // Fall back to form input if meta not found
    const inputToken = document.querySelector('input[name="csrf_token"]');
    if (inputToken) {
        return inputToken.value;
    }
    
    console.error('CSRF token not found in page');
    return '';
}

// Form validation helpers
const validators = {
    required: (value) => !!value && value.trim().length > 0,
    email: (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
    phone: (value) => /^\+[1-9]\d{1,14}$/.test(value),
    minLength: (value, length) => value.length >= length,
    matches: (value, field) => value === document.getElementById(field).value
};

