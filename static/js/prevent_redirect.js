
// This script runs immediately when loaded
console.log("Preventing form redirects - script loaded");

// Run as soon as DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Find the decrypt form
    const decryptForm = document.getElementById('decrypt-form');
    
    if (decryptForm) {
        console.log("Found decrypt form - attaching event handlers");
        
        // Directly attach event listener to prevent ANY form submission
        decryptForm.onsubmit = function(e) {
            // Stop the form from submitting normally - use multiple methods for redundancy
            e.preventDefault();
            e.stopPropagation();
            console.log("FORM SUBMISSION PREVENTED");
            
            // Get the form data
            const formData = new FormData(decryptForm);
            
            // Show result area if we already have it
            const resultArea = document.getElementById('decryption-result');
            if (resultArea) {
                resultArea.style.display = 'block';
            }
            
            // Show loading if we have it
            const loadingIndicator = document.getElementById('loading-indicator');
            if (loadingIndicator) {
                loadingIndicator.style.display = 'block';
            }
            
            // Use fetch API to submit the form
            fetch('/decrypt', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                console.log("Response data:", data);
                
                // Hide loading if shown
                if (loadingIndicator) {
                    loadingIndicator.style.display = 'none';
                }
                
                if (data.success && data.decrypted_message) {
                    // Find the textarea for the message
                    const messageArea = document.getElementById('decrypted-message');
                    if (messageArea) {
                        // Show the message
                        messageArea.value = data.decrypted_message;
                        
                        // Make sure result container is visible
                        const resultContainer = document.getElementById('decryption-result');
                        if (resultContainer) {
                            resultContainer.style.display = 'block';
                            
                            // Scroll to it
                            resultContainer.scrollIntoView({behavior: 'smooth'});
                        }
                    } else {
                        // Fallback - show in alert
                        alert("Decrypted message: " + data.decrypted_message);
                    }
                } else {
                    // Show error
                    alert(data.message || "Error decrypting message");
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert("An error occurred while communicating with the server");
                if (loadingIndicator) {
                    loadingIndicator.style.display = 'none';
                }
            });
            
            // Return false to prevent the form from submitting
            return false;
        };
        
        // Add another layer of protection - intercept button click
        const submitButton = decryptForm.querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.onclick = function(e) {
                e.preventDefault();
                console.log("Submit button clicked - preventing default");
                return false;
            };
        }
    } else {
        console.error("Could not find decrypt form with ID 'decrypt-form'");
    }
});
