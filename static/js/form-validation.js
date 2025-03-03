/**
 * Enhanced form validation for SteganoSafe
 */

document.addEventListener('DOMContentLoaded', function() {
    // Phone number validation
    const phoneInputs = document.querySelectorAll('input[name="phone_number"]');
    
    phoneInputs.forEach(input => {
        input.addEventListener('input', function() {
            validatePhone(this);
        });
        
        // Initial validation if field has value
        if (input.value) {
            validatePhone(input);
        }
    });
    
    function validatePhone(input) {
        const value = input.value.trim();
        const errorElement = document.getElementById('phone-error') || 
                            input.parentElement.querySelector('.invalid-feedback') ||
                            document.createElement('div');
                            
        if (!errorElement.id) {
            errorElement.id = 'phone-error';
            errorElement.className = 'invalid-feedback';
            input.parentElement.appendChild(errorElement);
        }
        
        // Clear previous error
        errorElement.textContent = '';
        input.classList.remove('is-invalid');
        errorElement.classList.add('d-none');
        
        if (value) {
            // Clean the input value (remove spaces, parentheses, dashes)
            const cleanedValue = value.replace(/[\s\-\(\)]/g, '');
            
            // E.164 format validation: + followed by 1-15 digits, first digit can't be 0
            const e164Regex = /^\+[1-9]\d{1,14}$/;
            
            if (!cleanedValue.startsWith('+')) {
                errorElement.textContent = "Phone number must start with + symbol";
                input.classList.add('is-invalid');
                errorElement.classList.remove('d-none');
                return false;
            }
            
            if (!e164Regex.test(cleanedValue)) {
                errorElement.textContent = "Invalid format. Must be: +[country code][number]";
                input.classList.add('is-invalid');
                errorElement.classList.remove('d-none');
                return false;
            }
            
            // If we've made it this far, update the input with the cleaned value
            if (input.value !== cleanedValue) {
                input.value = cleanedValue;
            }
            
            // Valid phone number
            input.classList.add('is-valid');
            return true;
        }
        
        return true; // Empty is considered valid at this stage
    }
    
    // Form submission validation
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            // Get phone input
            const phoneInput = this.querySelector('input[name="phone_number"]');
            
            if (phoneInput) {
                // Clean the phone number before submitting
                phoneInput.value = phoneInput.value.replace(/[\s\-\(\)]/g, '');
                
                if (!validatePhone(phoneInput)) {
                    e.preventDefault();
                    // Scroll to the phone field
                    phoneInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    
                    // Show error alert
                    Swal.fire({
                        icon: 'warning',
                        title: 'Invalid Phone Format',
                        text: 'Please enter a valid phone number in E.164 format (e.g., +1234567890)',
                        confirmButtonColor: '#2c7da0'
                    });
                    return false;
                }
            }
        });
    }
    
    // Auto-validate OTP in development mode
    if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
        console.log("Development mode: OTP validation simplified");
        
        // For the OTP button in Register form
        const requestOtpBtn = document.getElementById('requestOtpBtn');
        const otpField = document.querySelector('input[name="otp"]');
        
        if (requestOtpBtn && otpField) {
            // Add development shortcut for OTP
            requestOtpBtn.addEventListener('click', function(e) {
                // In dev mode, just fill in a default OTP value
                setTimeout(() => {
                    otpField.value = '123456';
                    
                    // Set phone as validated
                    const phoneValidatedInput = document.getElementById('phone_validated');
                    if (phoneValidatedInput) {
                        phoneValidatedInput.value = 'true';
                    }
                    
                    Swal.fire({
                        icon: 'info',
                        title: 'Development Mode',
                        text: 'OTP auto-filled with test value: 123456',
                        confirmButtonColor: '#2c7da0'
                    });
                }, 500);
            });
        }
    }
});

/**
 * Form validation helper functions
 */

// Email validation
function validateEmail(email) {
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

// Phone number validation (basic E.164 format)
function validatePhone(phone) {
    // Accept numbers that start with + and have at least 6 digits
    return phone.startsWith('+') && phone.replace(/\D/g, '').length >= 6;
}

// Password strength check
function checkPasswordStrength(password) {
    let strength = 0;
    
    // Length check
    if (password.length >= 8) strength += 1;
    
    // Character type checks
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength += 1;
    if (/\d/.test(password)) strength += 1;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 1;
    
    return {
        score: strength,
        max: 4,
        text: strength <= 1 ? 'Weak' : strength <= 2 ? 'Moderate' : strength <= 3 ? 'Good' : 'Strong'
    };
}

// Form field validator
function validateFormField(field, validationFunction, errorMessage) {
    const isValid = validationFunction(field.value);
    
    // Get error container (sibling or child of parent)
    const parent = field.parentNode;
    let errorContainer = parent.querySelector('.invalid-feedback');
    
    // Create error container if it doesn't exist
    if (!errorContainer) {
        errorContainer = document.createElement('div');
        errorContainer.className = 'invalid-feedback';
        parent.appendChild(errorContainer);
    }
    
    if (isValid) {
        field.classList.remove('is-invalid');
        field.classList.add('is-valid');
        errorContainer.style.display = 'none';
    } else {
        field.classList.remove('is-valid');
        field.classList.add('is-invalid');
        errorContainer.textContent = errorMessage;
        errorContainer.style.display = 'block';
    }
    
    return isValid;
}
