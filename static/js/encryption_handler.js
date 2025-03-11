/**
 * Encryption Handler
 * Handles client-side functionality for the encryption process
 */

document.addEventListener('DOMContentLoaded', function() {
    console.log("Encryption handler initialized");
    
    // Get form elements
    const encryptForm = document.getElementById('encrypt-form');
    if (!encryptForm) {
        console.error("Encrypt form not found");
        return;
    }
    
    // Image preview functionality
    const imageInput = document.getElementById('image');
    const previewContainer = document.querySelector('.form-preview');
    const previewPlaceholder = document.querySelector('.preview-placeholder');
    
    if (imageInput && previewContainer) {
        imageInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const file = this.files[0];
                
                // Size validation (max 5MB)
                if (file.size > 5 * 1024 * 1024) {
                    showAlert('Image file too large. Maximum size is 5MB', 'danger');
                    this.value = '';
                    return;
                }
                
                // Type validation
                if (!file.type.startsWith('image/')) {
                    showAlert('Please select a valid image file (JPEG, PNG, etc.)', 'danger');
                    this.value = '';
                    return;
                }
                
                const reader = new FileReader();
                reader.onload = function(e) {
                    // Clear placeholder
                    if (previewPlaceholder) {
                        previewPlaceholder.style.display = 'none';
                    }
                    
                    // Check if preview already exists
                    let previewImg = previewContainer.querySelector('img');
                    
                    if (!previewImg) {
                        previewImg = document.createElement('img');
                        previewContainer.appendChild(previewImg);
                    }
                    
                    previewImg.src = e.target.result;
                };
                
                reader.readAsDataURL(file);
                
                // Debug
                console.log(`Image selected: ${file.name}, ${Math.round(file.size/1024)}KB`);
            }
        });
    }
    
    // Form submission handler
    if (encryptForm) {
        encryptForm.addEventListener('submit', function(e) {
            e.preventDefault();
            console.log("Encrypt form submission triggered");
            
            // Validate form
            if (!validateEncryptForm()) {
                console.log("Form validation failed");
                return;
            }
            
            // Show progress
            const progressContainer = document.querySelector('.progress-container');
            const progressBar = document.querySelector('.progress-bar');
            if (progressContainer) {
                progressContainer.style.display = 'block';
            }
            
            // Disable submit button
            const submitBtn = encryptForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerHTML : '';
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
            }
            
            // Get form data
            const formData = new FormData(this);
            
            // Debug form data
            console.log("Encrypting with form data:");
            for (let [key, value] of formData.entries()) {
                console.log(`${key}: ${value instanceof File ? value.name : value}`);
            }
            
            // Animate progress bar for visual feedback
            let progress = 0;
            const interval = setInterval(function() {
                progress += 5;
                if (progressBar) {
                    progressBar.style.width = Math.min(progress, 90) + '%';
                }
                if (progress >= 90) clearInterval(interval);
            }, 300);
            
            // Get CSRF token from meta tag
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            
            // Send request
            fetch('/encrypt', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRF-Token': csrfToken
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Server responded with status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Clear interval for progress bar animation
                clearInterval(interval);
                
                // Set progress to 100%
                if (progressBar) {
                    progressBar.style.width = '100%';
                }
                
                if (data.success) {
                    showAlert(data.message || 'Message successfully encrypted!', 'success');
                    
                    // Redirect after a short delay
                    setTimeout(function() {
                        window.location.href = data.redirect || '/dashboard';
                    }, 1500);
                } else {
                    // Show error
                    showAlert(data.message || 'Encryption failed. Please try again.', 'danger');
                    
                    // Reset submit button
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = originalBtnText;
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                
                // Show error
                showAlert(error.message || 'An error occurred. Please try again.', 'danger');
                
                // Reset submit button
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalBtnText;
                }
                
                // Hide progress
                if (progressContainer) {
                    progressContainer.style.display = 'none';
                }
            });
        });
    }
    
    // Form validation
    function validateEncryptForm() {
        // Get form fields
        const imageInput = document.getElementById('image');
        const messageInput = document.getElementById('message');
        const passwordInput = document.getElementById('password');
        
        // Reset previous error states
        [imageInput, messageInput, passwordInput].forEach(input => {
            if (input) {
                input.classList.remove('is-invalid');
                const feedback = input.nextElementSibling;
                if (feedback && feedback.classList.contains('invalid-feedback')) {
                    feedback.textContent = '';
                }
            }
        });
        
        let isValid = true;
        
        // Validate image
        if (!imageInput || !imageInput.files || !imageInput.files[0]) {
            if (imageInput) {
                imageInput.classList.add('is-invalid');
                let feedback = imageInput.nextElementSibling;
                if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                    feedback = document.createElement('div');
                    feedback.className = 'invalid-feedback';
                    imageInput.parentNode.appendChild(feedback);
                }
                feedback.textContent = 'Please select an image file';
            }
            showAlert('Please select an image file', 'danger');
            isValid = false;
        }
        
        // Validate message
        if (!messageInput || !messageInput.value.trim()) {
            if (messageInput) {
                messageInput.classList.add('is-invalid');
                let feedback = messageInput.nextElementSibling;
                if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                    feedback = document.createElement('div');
                    feedback.className = 'invalid-feedback';
                    messageInput.parentNode.appendChild(feedback);
                }
                feedback.textContent = 'Please enter a message to hide';
            }
            showAlert('Please enter a message to hide', 'danger');
            isValid = false;
        }
        
        // Validate password
        if (!passwordInput || !passwordInput.value) {
            if (passwordInput) {
                passwordInput.classList.add('is-invalid');
                let feedback = passwordInput.nextElementSibling;
                if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                    feedback = document.createElement('div');
                    feedback.className = 'invalid-feedback';
                    passwordInput.parentNode.appendChild(feedback);
                }
                feedback.textContent = 'Please enter a password for encryption';
            }
            showAlert('Please enter a password for encryption', 'danger');
            isValid = false;
        }
        
        return isValid;
    }
    
    // Helper function to show alerts
    function showAlert(message, type) {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Find container for alert
        const container = document.querySelector('.alert-container') || document.querySelector('.container');
        
        // Insert at the beginning of the container
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
        } else {
            // If no container found, insert before the form
            if (encryptForm) {
                encryptForm.parentNode.insertBefore(alertDiv, encryptForm);
            }
        }
        
        // Auto dismiss after 5 seconds
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alertDiv);
            bsAlert.close();
        }, 5000);
    }
    
    // Fix the form submission function to ensure encryption method is properly sent
    document.addEventListener('DOMContentLoaded', function() {
        const encryptForm = document.getElementById('encrypt-form');
        if (!encryptForm) return;
        
        // Override form submission to ensure encryption method is included
        encryptForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Validate form
            if (!validateEncryptForm()) {
                return;
            }
            
            // Get encryption method
            const methodSelector = document.querySelector('select[name="encryption_method"]');
            const selectedMethod = methodSelector ? methodSelector.value : 'LSB';
            
            // Debug output
            console.log(`Encrypting with method: ${selectedMethod}`);
            
            // Show progress
            const progressContainer = document.querySelector('.progress-container');
            const progressBar = document.querySelector('.progress-bar');
            if (progressContainer) {
                progressContainer.style.display = 'block';
            }
            
            // Disable submit button
            const submitBtn = encryptForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerHTML : '';
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
            }
            
            // Get form data
            const formData = new FormData(this);
            
            // Ensure encryption method is set
            if (selectedMethod && !formData.has('encryption_method')) {
                formData.append('encryption_method', selectedMethod);
            }
            
            // Debug form data
            console.log("Encrypting with form data:");
            for (let [key, value] of formData.entries()) {
                console.log(`${key}: ${value instanceof File ? value.name : value}`);
            }
            
            // Animate progress bar for visual feedback
            let progress = 0;
            const interval = setInterval(function() {
                progress += 5;
                if (progressBar) {
                    progressBar.style.width = Math.min(progress, 90) + '%';
                }
                if (progress >= 90) clearInterval(interval);
            }, 300);
            
            // Get CSRF token from meta tag
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            
            // Send request
            fetch('/encrypt', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRF-Token': csrfToken
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Server responded with status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Clear interval for progress bar animation
                clearInterval(interval);
                
                // Set progress to 100%
                if (progressBar) {
                    progressBar.style.width = '100%';
                }
                
                if (data.success) {
                    showAlert(data.message || 'Message successfully encrypted!', 'success');
                    
                    // Redirect after a short delay
                    setTimeout(function() {
                        window.location.href = data.redirect || '/dashboard';
                    }, 1500);
                } else {
                    // Show error
                    showAlert(data.message || 'Encryption failed. Please try again.', 'danger');
                    
                    // Reset submit button
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = originalBtnText;
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                
                // Show error
                showAlert(error.message || 'An error occurred. Please try again.', 'danger');
                
                // Reset submit button
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalBtnText;
                }
                
                // Hide progress
                if (progressContainer) {
                    progressContainer.style.display = 'none';
                }
            });
        });
        
        // Rest of the code remains the same
        // ...existing code...
    });
});
