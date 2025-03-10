/**
 * Dashboard decrypt functionality
 * Handles decryption of stored images
 */

// Wait for document to be ready
document.addEventListener('DOMContentLoaded', function() {
    // Set up decrypt modal handling
    setupDecryptModal();
    
    // Set up decrypt buttons
    setupDecryptButtons();
    
    // Debug log
    console.log('Decrypt functionality initialized');
});

function setupDecryptModal() {
    // Get the modal element
    const decryptModal = document.getElementById('decryptModal');
    
    // Handle modal events
    if (decryptModal) {
        // When the modal is shown, focus on the password input
        decryptModal.addEventListener('shown.bs.modal', function(event) {
            const button = event.relatedTarget;
            const imageId = button.getAttribute('data-image-id');
            
            // Set the image ID in the form
            document.getElementById('decrypt-image-id').value = imageId;
            
            // Focus on password field
            document.getElementById('decrypt-password').focus();
            
            // Log for debugging
            console.log('Decrypt modal opened for image ID:', imageId);
        });
    }
}

// Update the setupDecryptButtons function to handle the enhanced error display
function setupDecryptButtons() {
    // Get the decrypt form
    const decryptForm = document.getElementById('decrypt-form');
    
    // Handle decrypt form submission
    if (decryptForm) {
        decryptForm.addEventListener('submit', function(event) {
            // Prevent the default form submission
            event.preventDefault();
            
            // Get form data
            const imageId = document.getElementById('decrypt-image-id').value;
            const password = document.getElementById('decrypt-password').value;
            const method = document.querySelector('input[name="decrypt-method"]:checked')?.value || 'LSB';
            
            // Log for debugging
            console.log('Decrypting image:', imageId, 'using method:', method);
            
            // Show loading state
            showDecryptLoading(true);
            
            // Hide any previous tips
            const tips = document.getElementById('password-tips');
            if (tips) tips.remove();
            
            // Make API request to decrypt
            decryptImage(imageId, password, method)
                .then(response => {
                    if (response.success) {
                        // Check if this was a recovered message
                        const isRecovered = response.decrypted_message.includes('[RECOVERED]') || 
                                          response.decrypted_message.includes('[EMERGENCY');
                                          
                        // Show success message with decrypted text
                        showDecryptResult(response.decrypted_message, true);
                        
                        if (isRecovered) {
                            // For recovered messages, add a note
                            const noteElement = document.createElement('div');
                            noteElement.className = 'alert alert-warning mt-2';
                            noteElement.textContent = 'This message was recovered using emergency measures ' +
                                                      'and may not be complete or accurate.';
                            document.getElementById('decrypt-result-container').after(noteElement);
                        }
                        
                        console.log('Decryption successful' + (isRecovered ? ' (recovered)' : ''));
                    } else {
                        // Show error message
                        showDecryptResult(response.message || 'Failed to decrypt message', false);
                        console.error('Decryption failed:', response.message || 'Unknown error');
                    }
                })
                .catch(error => {
                    // Show error message with suggestions
                    showDecryptResult(error.message || 'Failed to decrypt message', false, error.suggestions);
                    console.error('Decryption error:', error);
                })
                .finally(() => {
                    // Hide loading state
                    showDecryptLoading(false);
                });
        });
    }
    
    // Clear button handling
    const clearBtn = document.getElementById('decrypt-clear-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', function() {
            document.getElementById('decrypt-result').textContent = '';
            document.getElementById('decrypt-result-container').classList.add('d-none');
            document.getElementById('decrypt-password').value = '';
            
            // Remove any tips or additional messages
            const tips = document.getElementById('password-tips');
            if (tips) tips.remove();
            
            // Remove any recovery notes
            const notes = document.querySelectorAll('.alert.alert-warning');
            notes.forEach(note => note.remove());
        });
    }
}

function showDecryptLoading(isLoading) {
    const submitBtn = document.getElementById('decrypt-submit-btn');
    const spinner = document.getElementById('decrypt-spinner');
    
    if (isLoading) {
        submitBtn.disabled = true;
        spinner.classList.remove('d-none');
    } else {
        submitBtn.disabled = false;
        spinner.classList.add('d-none');
    }
}

function showDecryptResult(message, isSuccess, suggestions = null) {
    const resultContainer = document.getElementById('decrypt-result-container');
    const resultElement = document.getElementById('decrypt-result');
    
    // Set result text
    resultElement.textContent = message;
    
    // Show container
    resultContainer.classList.remove('d-none');
    
    // Set success/error styling
    if (isSuccess) {
        resultContainer.classList.remove('alert-danger');
        resultContainer.classList.add('alert-success');
    } else {
        resultContainer.classList.remove('alert-success');
        resultContainer.classList.add('alert-danger');
        
        // Add suggestions if provided
        if (suggestions && suggestions.length > 0) {
            const suggestionsList = document.createElement('ul');
            suggestionsList.className = 'mt-2 text-muted';
            
            suggestions.forEach(suggestion => {
                const item = document.createElement('li');
                item.textContent = suggestion;
                suggestionsList.appendChild(item);
            });
            
            // Clear previous suggestions if any
            const oldSuggestions = resultElement.nextElementSibling;
            if (oldSuggestions && oldSuggestions.tagName === 'UL') {
                oldSuggestions.remove();
            }
            
            resultElement.parentNode.appendChild(suggestionsList);
        }
    }
}

async function decryptImage(imageId, password, method) {
    return new Promise((resolve, reject) => {
        // Show suggestions for common password issues while waiting
        const suggestionTimer = setTimeout(() => {
            showPasswordSuggestions();
        }, 2000);  // Show after 2 seconds of waiting
        
        // Make API request directly to the working endpoint
        console.log('Making API request to decrypt image');
        
        // Use fetch API with the correct endpoint
        fetch('/api/decrypt_saved_image', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                image_id: imageId,
                password: password,
                method: method,
                try_recovery: true  // Add this flag to attempt recovery methods
            })
        })
        .then(response => {
            clearTimeout(suggestionTimer);  // Clear the timer
            return response.json().then(data => {
                if (!response.ok) {
                    // Enhanced error handling - extract detailed error info
                    const errorMsg = data.message || data.error || 'Failed to decrypt image';
                    const error = new Error(errorMsg);
                    error.details = data.details || '';
                    error.code = response.status;
                    error.suggestions = getDecryptionErrorSuggestions(error.code, errorMsg);
                    throw error;
                }
                return data;
            });
        })
        .then(data => {
            resolve(data);  // Success!
        })
        .catch(error => {
            clearTimeout(suggestionTimer);  // Make sure the timer is cleared
            console.error('Error decrypting image:', error);
            
            // Add helpful suggestions based on the error
            if (!error.suggestions) {
                error.suggestions = getDecryptionErrorSuggestions(0, error.message);
            }
            
            reject(error);
        });
    });
}

function showPasswordSuggestions() {
    // Show a temporary message with password tips while waiting for decryption
    const tipsContainer = document.createElement('div');
    tipsContainer.id = 'password-tips';
    tipsContainer.className = 'alert alert-info mt-3';
    tipsContainer.innerHTML = `
        <h5>Still working on decryption...</h5>
        <p>Make sure your password is correct. Common issues include:</p>
        <ul>
            <li>Incorrect capitalization</li>
            <li>Typing mistakes</li>
            <li>Using a different password than when encrypting</li>
        </ul>
    `;
    
    // Add to the modal if not already there
    const modalBody = document.querySelector('.modal-body');
    if (modalBody && !document.getElementById('password-tips')) {
        modalBody.appendChild(tipsContainer);
    }
}

function getDecryptionErrorSuggestions(code, errorMsg) {
    const suggestions = [];
    
    if (errorMsg.includes('password')) {
        suggestions.push('Double check that you entered the correct password');
        suggestions.push('Try variations of your password (uppercase/lowercase)');
        suggestions.push('Password is case-sensitive');
    }
    
    if (errorMsg.includes('corrupted')) {
        suggestions.push('The image may have been modified or damaged');
        suggestions.push('Try decrypting with PVD method instead');
    }
    
    if (code === 404) {
        suggestions.push('The image could not be found on the server');
        suggestions.push('Try refreshing the page and decrypting again');
    }
    
    // Always add these general suggestions
    if (suggestions.length === 0) {
        suggestions.push('Make sure you used the correct decryption method');
        suggestions.push('Try decrypting again with the same password');
        suggestions.push('If problems persist, try re-encrypting your message in a new image');
    }
    
    return suggestions;
}
