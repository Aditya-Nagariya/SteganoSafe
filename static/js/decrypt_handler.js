document.addEventListener('DOMContentLoaded', function() {
    console.log("Decrypt handler script loaded!");
    
    const decryptForm = document.getElementById('decrypt-form');
    const loadingIndicator = document.getElementById('loading-indicator');
    const decryptContainer = document.getElementById('decrypt-container');
    const resultContainer = document.getElementById('decryption-result');
    const decryptedMessageElem = document.getElementById('decrypted-message');
    const copyBtn = document.getElementById('copy-message');
    const decryptAnotherBtn = document.getElementById('decrypt-another');
    
    // Debug check that all elements are found
    console.log("Found decrypt form:", !!decryptForm);
    console.log("Found loading indicator:", !!loadingIndicator);
    console.log("Found decrypt container:", !!decryptContainer);
    console.log("Found result container:", !!resultContainer);
    console.log("Found message textarea:", !!decryptedMessageElem);
    
    if (decryptForm) {
        // Attach submit handler to the form
        decryptForm.addEventListener('submit', function(e) {
            // Explicitly prevent default form submission
            e.preventDefault();
            console.log("Form submission intercepted");
            
            // Clear any previous results
            if (decryptedMessageElem) {
                decryptedMessageElem.value = '';
            }
            
            // Show loading indicator
            if (loadingIndicator) {
                loadingIndicator.style.display = 'block';
                console.log("Showing loading indicator");
            }
            
            // Get form data
            const formData = new FormData(decryptForm);
            
            // Log formData for debugging (excluding password)
            console.log("Form data prepared, submitting to server");
            console.log("Has file:", formData.has('image'));
            
            // Make AJAX request
            fetch('/decrypt', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': getCsrfToken()
                }
            })
            .then(response => {
                console.log("Server response received, status:", response.status);
                return response.json();
            })
            .then(data => {
                console.log("Response data:", data);
                
                // Hide loading indicator
                if (loadingIndicator) {
                    loadingIndicator.style.display = 'none';
                }
                
                if (data.success) {
                    console.log("Decryption successful");
                    
                    // Check for decrypted message in the response
                    if (data.decrypted_message) {
                        console.log("Message found in response");
                        
                        if (decryptedMessageElem && resultContainer) {
                            // Set the message in the textarea
                            decryptedMessageElem.value = data.decrypted_message;
                            console.log("Message set in textarea");
                            
                            // Show the result container
                            resultContainer.style.display = 'block';
                            console.log("Result container now visible");
                            
                            // Scroll to the results
                            resultContainer.scrollIntoView({behavior: 'smooth'});
                        } else {
                            console.error("Result display elements not found!");
                            showAlert('Message decrypted: ' + data.decrypted_message, 'success');
                        }
                    }
                    // Handle legacy response with redirect
                    else if (data.redirect) {
                        console.log("Legacy redirect response detected:", data.redirect);
                        
                        try {
                            // Try to extract message from URL
                            const url = new URL(data.redirect, window.location.origin);
                            const message = url.searchParams.get('message');
                            
                            if (message && decryptedMessageElem && resultContainer) {
                                decryptedMessageElem.value = message;
                                resultContainer.style.display = 'block';
                                resultContainer.scrollIntoView({behavior: 'smooth'});
                            } else {
                                console.log("Couldn't extract message or display elements not found, redirecting");
                                window.location.href = data.redirect;
                            }
                        } catch (e) {
                            console.error("Error parsing redirect URL:", e);
                            window.location.href = data.redirect;
                        }
                    } else {
                        console.error("No message or redirect in response!");
                        showAlert("Decryption succeeded but no message was returned", 'warning');
                    }
                } else {
                    console.error("Decryption failed:", data.message);
                    showAlert(data.message || 'Error decrypting message', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('An error occurred while communicating with the server.', 'danger');
                if (loadingIndicator) loadingIndicator.style.display = 'none';
            });
        });
    } else {
        console.error("Decrypt form not found! The form must have id='decrypt-form'");
    }
    
    // Handle copy button
    if (copyBtn && decryptedMessageElem) {
        copyBtn.addEventListener('click', function() {
            decryptedMessageElem.select();
            document.execCommand('copy');
            
            const originalHTML = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="bi bi-check-lg"></i>';
            copyBtn.classList.add('btn-success');
            copyBtn.classList.remove('btn-outline-secondary');
            
            setTimeout(() => {
                copyBtn.innerHTML = originalHTML;
                copyBtn.classList.remove('btn-success');
                copyBtn.classList.add('btn-outline-secondary');
            }, 1500);
        });
    }
    
    // Handle decrypt another button
    if (decryptAnotherBtn && decryptForm) {
        decryptAnotherBtn.addEventListener('click', function() {
            decryptForm.reset();
            
            if (resultContainer) {
                resultContainer.style.display = 'none';
            }
            
            const fileInput = document.getElementById('image');
            if (fileInput) {
                fileInput.focus();
            }
        });
    }
    
    // Helper functions
    function getCsrfToken() {
        // First try meta tag
        const metaToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (metaToken) return metaToken;
        
        // Then try form input
        const inputToken = document.querySelector('input[name="csrf_token"]')?.value;
        if (inputToken) return inputToken;
        
        console.error("CSRF token not found!");
        return '';
    }
    
    function showAlert(message, type = 'info') {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Find where to insert the alert
        if (decryptForm) {
            const parent = decryptForm.parentNode;
            const insertBefore = decryptForm;
            
            // Insert alert before the form
            parent.insertBefore(alertDiv, insertBefore);
        } else {
            // Fallback - append to body
            document.body.appendChild(alertDiv);
        }
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }, 5000);
    }
});
