document.addEventListener('DOMContentLoaded', function() {
    console.log("Registration form script loaded");
    
    // Set the phone validated field to true in development mode
    const isDevMode = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    if (isDevMode) {
        console.log("Development mode detected - skipping OTP validation");
        // If phone_validated field exists, set it to true for dev environment
        const phoneValidatedField = document.getElementById('phone_validated');
        if (phoneValidatedField) {
            phoneValidatedField.value = 'true';
        }
    }
    
    // Form submission handler with error handling
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(event) {
            if (isDevMode) {
                // In development mode, don't do client-side validation
                return true;
            }
            
            event.preventDefault();
            
            // Reset previous errors
            document.querySelectorAll('.is-invalid').forEach(el => {
                el.classList.remove('is-invalid');
            });
            
            // Get form data
            const formData = new FormData(registerForm);
            
            // Verify that passwords match
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (password !== confirmPassword) {
                alert('Passwords do not match!');
                return false;
            }
            
            // Submit the form
            registerForm.submit();
        });
    }
    
    // Development mode message
    if (isDevMode) {
        console.log("DEVELOPMENT MODE: OTP validation simplified");
    }
});
