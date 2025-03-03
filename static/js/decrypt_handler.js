/**
 * Handles the decryption process with improved error handling
 */

document.addEventListener('DOMContentLoaded', function() {
    const decryptForm = document.getElementById('decryptForm');
    if (!decryptForm) return;

    decryptForm.addEventListener('submit', function(e) {
        e.preventDefault();
        console.log('Decrypt form submission intercepted');
        
        // Show loading state
        const submitButton = this.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Decrypting...';
        submitButton.disabled = true;
        
        // Get CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        
        // Prepare form data
        const formData = new FormData(this);
        
        // Debug log
        console.log('Sending decrypt request to:', this.action);
        
        fetch(this.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': csrfToken
            },
            credentials: 'same-origin'
        })
        .then(response => {
            console.log('Received response:', response.status);
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || `Server error: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            console.log('Decrypt response data:', data);
            
            // Reset button state
            submitButton.innerHTML = originalButtonText;
            submitButton.disabled = false;
            
            if (data.success) {
                // Parse the URL to get the message parameter
                let message;
                try {
                    const urlParams = new URLSearchParams(new URL(data.redirect, window.location.origin).search);
                    message = urlParams.get('message');
                } catch (error) {
                    console.error('Error parsing redirect URL:', error);
                    message = null;
                }
                
                if (message) {
                    const resultDiv = document.getElementById('decryptResult');
                    const messageElem = document.getElementById('decryptedMessage');
                    
                    messageElem.textContent = message;
                    resultDiv.classList.remove('d-none');
                    
                    // Scroll to result
                    resultDiv.scrollIntoView({behavior: "smooth", block: "start"});
                    
                    // Add animation to highlight the result
                    resultDiv.classList.add('animate__animated', 'animate__fadeIn');
                } else {
                    // If we can't parse the message, redirect to the result page
                    window.location.href = data.redirect;
                }
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'Decryption Failed',
                    text: data.message || 'Unable to decrypt the message.',
                    confirmButtonColor: '#4361ee'
                });
            }
        })
        .catch(error => {
            console.error('Decryption error:', error);
            
            // Reset button state
            submitButton.innerHTML = originalButtonText;
            submitButton.disabled = false;
            
            Swal.fire({
                icon: 'error',
                title: 'Decryption Error',
                text: error.message || 'There was a problem with the decryption process.',
                confirmButtonColor: '#4361ee'
            });
        });
    });
});
