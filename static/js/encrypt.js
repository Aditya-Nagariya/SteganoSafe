document.addEventListener('DOMContentLoaded', function() {
    // Get the encryption form
    const encryptForm = document.getElementById('encrypt-form');
    if (!encryptForm) return;
    
    // Log form found for debugging
    console.log('Encryption form found, attaching handlers');
    
    // Handle form submission
    encryptForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        console.log('Encryption form submitted');
        
        // Show loading state
        const submitButton = encryptForm.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
        submitButton.disabled = true;
        
        // Get form data
        const formData = new FormData(encryptForm);
        
        // Simple validation
        const image = formData.get('image');
        const message = formData.get('message');
        const password = formData.get('password');
        
        let hasError = false;
        let errorMessage = '';
        
        if (!image || image.size === 0) {
            hasError = true;
            errorMessage = 'Please select an image file';
        } else if (!message) {
            hasError = true;
            errorMessage = 'Please enter a message to hide';
        } else if (!password) {
            hasError = true;
            errorMessage = 'Please enter an encryption password';
        }
        
        if (hasError) {
            submitButton.innerHTML = originalButtonText;
            submitButton.disabled = false;
            showAlert(errorMessage, 'danger');
            return;
        }
        
        // Get CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        
        // Send AJAX request
        fetch('/encrypt', {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRFToken': csrfToken
            }
        })
        .then(response => {
            console.log('Encryption response received');
            if (!response.ok) {
                throw new Error(`Server responded with ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Encryption response data:', data);
            if (data.success) {
                showAlert(data.message || 'Encryption successful!', 'success');
                setTimeout(() => {
                    window.location.href = data.redirect || '/dashboard';
                }, 1500);
            } else {
                throw new Error(data.message || 'Unknown error occurred');
            }
        })
        .catch(error => {
            console.error('Encryption error:', error);
            showAlert(`Error: ${error.message}`, 'danger');
            submitButton.innerHTML = originalButtonText;
            submitButton.disabled = false;
        });
    });
    
    // Function to show alert messages
    function showAlert(message, type) {
        const alertContainer = document.querySelector('.alert-container');
        if (!alertContainer) {
            // Create alert container if it doesn't exist
            const container = document.querySelector('.container');
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert-container';
            container.insertBefore(alertDiv, container.firstChild);
        }
        
        // Create alert
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Add to page
        document.querySelector('.alert-container').appendChild(alert);
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            alert.classList.remove('show');
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    }
});
