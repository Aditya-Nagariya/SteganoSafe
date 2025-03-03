/**
 * Development Helper Functions
 * These should NOT be included in production!
 */

// Show OTP in development mode
function showOtpAlert() {
    if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {
        // Always use the development OTP
        alert("DEVELOPMENT MODE: Use OTP 123456 for testing");
    }
}

// Auto-fill OTP for testing
function autoFillOtp() {
    if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {
        const otpField = document.getElementById('otp_field');
        if (otpField) {
            otpField.value = "123456";
            console.log("Auto-filled development OTP: 123456");
        }
    }
}

// Add to window for global access
window.devHelpers = {
    showOtpAlert: showOtpAlert,
    autoFillOtp: autoFillOtp
};

// Debug alert
console.log("%c DEVELOPMENT HELPERS LOADED ", "background: #222; color: #bada55; font-size: 16px");
