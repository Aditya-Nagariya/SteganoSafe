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
const auth = getAuth(app);

// Render invisible reCAPTCHA on page load.
window.onload = function() {
    window.recaptchaVerifier = new RecaptchaVerifier('requestOtpBtn', {
        size: 'invisible',
        callback: function(response) {
            console.log("reCAPTCHA solved, OTP can be requested");
        }
    }, auth);
};

function requestFirebaseOtp() {
    const phoneNumber = document.getElementById('phone_number').value;
    if (!phoneNumber) {
        alert("Enter phone number first.");
        return;
    }
    const appVerifier = window.recaptchaVerifier;
    signInWithPhoneNumber(auth, phoneNumber, appVerifier)
    .then(confirmationResult => {
        window.confirmationResult = confirmationResult;
        alert("OTP sent successfully via Firebase.");
    })
    .catch(error => {
        console.error("Firebase OTP error:", error);
        alert("Error sending OTP: " + error.message);
    });
}

function confirmFirebaseOtp() {
    const otpInput = document.getElementById('otp_field').value;
    if (!otpInput) {
        alert("Please enter the OTP.");
        return;
    }
    window.confirmationResult.confirm(otpInput)
    .then(result => {
        alert("Phone number verified via Firebase!");
    })
    .catch(error => {
        console.error("Confirm OTP error:", error);
        alert("OTP verification failed: " + error.message);
    });
}