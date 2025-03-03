// Import the functions you need from the SDKs you need
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.3.1/firebase-app.js";
import { getAuth, RecaptchaVerifier, signInWithPhoneNumber } from "https://www.gstatic.com/firebasejs/11.3.1/firebase-auth.js";

// Your web app's Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyBq-5XWRSfh6uQ48nbjuZoGZwyeTRxtCcc",
    authDomain: "steganosafe.firebaseapp.com",
    projectId: "steganosafe",
    storageBucket: "steganosafe.firebasestorage.app",
    messagingSenderId: "34782480072",
    appId: "1:34782480072:web:e8247f95c6da58ccc407fd",
    measurementId: "G-N7DCRM1HRJ"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Global variables
let auth;
let recaptchaVerifier;
let confirmationResult;
let phoneNumberValid = false;
let useServerOtp = false; // Flag to use server-side OTP as fallback

// Initialize Firebase Auth with error handling
document.addEventListener('DOMContentLoaded', function() {
    try {
        auth = getAuth();
        console.log("Firebase Auth initialized");
    } catch (error) {
        console.error("Error initializing Firebase Auth, will use server OTP:", error);
        useServerOtp = true;
    }
});

// Function to request OTP (with Firebase or server fallback)
window.requestFirebaseOtp = function() {
    const phoneNumber = document.getElementById('phone_number').value;
    
    // Basic validation
    if (!phoneNumber) {
        showError("Please enter your phone number first");
        return;
    }

    // Display E.164 format message if not valid
    if (!phoneNumber.startsWith('+')) {
        showError("Phone number must start with + and country code (e.g., +1234567890)");
        return;
    }

    // Show loading state
    document.getElementById('requestOtpBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sending...';
    document.getElementById('requestOtpBtn').disabled = true;

    // Check for development mode
    const isDev = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost';
    
    // In development, show OTP debug info
    if (isDev) {
        console.log("%c DEVELOPMENT MODE: Use OTP 123456 for testing", "background: yellow; color: red; font-size: 16px; font-weight: bold;");
        
        // Use server OTP
        requestServerOtp(phoneNumber);
        
        // Show development OTP
        setTimeout(function() {
            if (window.devHelpers) {
                window.devHelpers.showOtpAlert();
                window.devHelpers.autoFillOtp();
            }
        }, 1000);
        
        return;
    }

    // Use server OTP if Firebase auth is unavailable
    if (useServerOtp) {
        console.log("Using server OTP instead of Firebase");
        requestServerOtp(phoneNumber);
        return;
    }

    // Initialize reCAPTCHA verifier if not already done
    if (!recaptchaVerifier) {
        try {
            recaptchaVerifier = new RecaptchaVerifier(auth, 'requestOtpBtn', {
                'size': 'invisible',
                'callback': (response) => {
                    console.log("reCAPTCHA verified");
                },
                'expired-callback': () => {
                    console.log("reCAPTCHA expired");
                    // Reset the verifier
                    recaptchaVerifier = null;
                }
            });
        } catch (error) {
            console.error("Error creating RecaptchaVerifier, fallback to server OTP:", error);
            requestServerOtp(phoneNumber);
            return;
        }
    }

    // Firebase phone authentication
    signInWithPhoneNumber(auth, phoneNumber, recaptchaVerifier)
        .then((result) => {
            // SMS sent. Store confirmation result for later verification
            confirmationResult = result;
            console.log("Firebase OTP sent successfully");
            
            // Change button state
            document.getElementById('requestOtpBtn').innerHTML = 'Resend OTP';
            document.getElementById('requestOtpBtn').disabled = false;
            
            // Show success message
            Swal.fire({
                icon: 'success',
                title: 'OTP Sent!',
                text: 'Please check your phone for the verification code.',
                timer: 3000
            });
            
            phoneNumberValid = true;
            
            // Focus on OTP field
            document.getElementById('otp_field').focus();
            
            // Add hidden field to form with phone validation status
            addPhoneValidationField();
        }).catch((error) => {
            console.error("Error sending Firebase OTP:", error);
            
            // Fall back to server OTP
            console.log("Falling back to server OTP");
            requestServerOtp(phoneNumber);
        });
};

// Server OTP request function
function requestServerOtp(phoneNumber) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    
    fetch("/request_otp", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRFToken': csrfToken
        },
        body: "phone=" + encodeURIComponent(phoneNumber)
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('requestOtpBtn').innerHTML = 'Resend OTP';
        document.getElementById('requestOtpBtn').disabled = false;
        
        if (data.success) {
            console.log("Server OTP sent successfully");
            
            Swal.fire({
                icon: 'success',
                title: 'OTP Sent!',
                text: 'Please check your phone (or server logs in development) for the verification code.',
                timer: 3000
            });
            
            phoneNumberValid = true;
            document.getElementById('otp_field').focus();
            
            // Add hidden field to form with phone validation status
            addPhoneValidationField();
            
            // Set flag to use server OTP verification
            useServerOtp = true;

            // For development, show OTP debug info
            if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {
                console.log("You can now view the OTP at: /dev/current_otp");
                // Automatically open the OTP viewer in a new tab
                window.open('/dev/current_otp', '_blank');
            }
        } else {
            showError(data.message || "Error sending OTP. Please try again.");
        }
    })
    .catch(error => {
        console.error("Error sending server OTP:", error);
        document.getElementById('requestOtpBtn').innerHTML = 'Request OTP';
        document.getElementById('requestOtpBtn').disabled = false;
        
        showError("Failed to send OTP. Please try again later.");
    });
}

// Add validation field to form
function addPhoneValidationField() {
    // Check if validation field already exists
    if (!document.querySelector('input[name="phone_validated"]')) {
        const validationField = document.createElement('input');
        validationField.type = 'hidden';
        validationField.name = 'phone_validated';
        validationField.value = 'true';
        document.querySelector('form').appendChild(validationField);
    }
}

// Verify OTP
window.confirmFirebaseOtp = function() {
    const otpCode = document.getElementById('otp_field').value;
    const phoneNumber = document.getElementById('phone_number').value;
    
    if (!otpCode || otpCode.length < 4) {
        showError("Please enter a valid OTP code");
        return;
    }
    
    // Show loading state
    const verifyButton = document.querySelector('button[onclick="confirmFirebaseOtp()"]');
    const originalText = verifyButton.innerHTML;
    verifyButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Verifying...';
    verifyButton.disabled = true;
    
    // If using server OTP verification
    if (useServerOtp) {
        verifyServerOtp(phoneNumber, otpCode, verifyButton, originalText);
        return;
    }
    
    // If using Firebase verification
    if (!confirmationResult) {
        showError("Please request an OTP first");
        verifyButton.innerHTML = originalText;
        verifyButton.disabled = false;
        return;
    }
    
    confirmationResult.confirm(otpCode)
        .then((result) => {
            // User signed in successfully with phone number
            const user = result.user;
            console.log("Firebase OTP confirmed successfully", user);
            
            // Update UI to show verified status
            verifyButton.innerHTML = '<i class="bi bi-check-circle-fill"></i> Verified';
            verifyButton.classList.remove('btn-info');
            verifyButton.classList.add('btn-success');
            
            // Add hidden field for OTP verification
            addOtpField(otpCode);
            
            // Show success message
            Swal.fire({
                icon: 'success',
                title: 'Phone Verified!',
                text: 'Your phone number has been verified successfully.',
                timer: 2000
            });
            
        }).catch((error) => {
            console.error("Error confirming Firebase OTP:", error);
            verifyButton.innerHTML = originalText;
            verifyButton.disabled = false;
            
            // Try server verification as fallback
            verifyServerOtp(phoneNumber, otpCode, verifyButton, originalText);
        });
};

// Server OTP verification function
function verifyServerOtp(phoneNumber, otpCode, verifyButton, originalText) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    
    fetch("/verify_otp", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRFToken': csrfToken
        },
        body: "phone=" + encodeURIComponent(phoneNumber) + "&otp=" + encodeURIComponent(otpCode)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log("Server OTP verified successfully");
            
            // Update UI to show verified status
            verifyButton.innerHTML = '<i class="bi bi-check-circle-fill"></i> Verified';
            verifyButton.classList.remove('btn-info');
            verifyButton.classList.add('btn-success');
            
            // Add hidden field for OTP verification
            addOtpField(otpCode);
            
            // Show success message
            Swal.fire({
                icon: 'success',
                title: 'Phone Verified!',
                text: 'Your phone number has been verified successfully.',
                timer: 2000
            });
        } else {
            verifyButton.innerHTML = originalText;
            verifyButton.disabled = false;
            showError(data.message || "Invalid OTP. Please try again.");
        }
    })
    .catch(error => {
        console.error("Error verifying server OTP:", error);
        verifyButton.innerHTML = originalText;
        verifyButton.disabled = false;
        showError("Verification failed. Please try again.");
    });
}

// Add OTP field to form
function addOtpField(otpCode) {
    const otpField = document.querySelector('input[name="otp"]');
    if (otpField) {
        otpField.value = otpCode;
    } else {
        const hiddenOtp = document.createElement('input');
        hiddenOtp.type = 'hidden';
        hiddenOtp.name = 'otp';
        hiddenOtp.value = otpCode;
        document.querySelector('form').appendChild(hiddenOtp);
    }
}

// Helper function to show error messages
function showError(message) {
    Swal.fire({
        icon: 'error',
        title: 'Error',
        text: message
    });
}