/**
 * Image Corruption Fix
 * 
 * This script helps detect and fix common issues with steganography images
 * that might prevent proper decryption
 */

document.addEventListener('DOMContentLoaded', function() {
    console.log("Image corruption fix initialized");
    
    // Watch for image uploads and preview them
    const imageInputs = document.querySelectorAll('input[type="file"][accept*="image"]');
    imageInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            if (this.files && this.files[0]) {
                const file = this.files[0];
                console.log(`Selected image: ${file.name}, ${file.type}, ${file.size} bytes`);
                
                // Check for potential corruption indicators
                checkImageForCorruption(file, this);
            }
        });
    });
    
    // Function to check image for common corruption issues
    function checkImageForCorruption(file, inputElement) {
        // Use FileReader to check image contents
        const reader = new FileReader();
        
        reader.onload = function(e) {
            const arrayBuffer = e.target.result;
            const byteArray = new Uint8Array(arrayBuffer);
            
            // Check for known corruption patterns
            
            // 1. Too many 'm' characters at beginning (seen in logs)
            let mCount = 0;
            const maxCheck = Math.min(1000, byteArray.length);
            for (let i = 0; i < maxCheck; i++) {
                if (byteArray[i] === 109) { // 'm' character ASCII code
                    mCount++;
                } else if (i > 0) {
                    break; // Count only leading 'm's
                }
            }
            
            if (mCount > 100) {
                console.warn(`Detected ${mCount} leading 'm' characters in file, potential corruption`);
                showCorruptionWarning(inputElement, "Image may be corrupted (leading 'm' characters detected)", "LSB");
                return;
            }
            
            // 2. Check for valid image header
            if (byteArray.length > 4) {
                // PNG signature: 89 50 4E 47
                const isPNG = byteArray[0] === 137 && byteArray[1] === 80 && 
                              byteArray[2] === 78 && byteArray[3] === 71;
                              
                // JPEG signature: FF D8 FF
                const isJPEG = byteArray[0] === 255 && byteArray[1] === 216 && byteArray[2] === 255;
                
                if (!isPNG && !isJPEG) {
                    console.warn("Invalid image signature, file might be corrupted");
                    showCorruptionWarning(inputElement, "Image format invalid or corrupted", "LSB");
                    return;
                }
            }
            
            // 3. Check for unusual file size (too small or too large)
            if (byteArray.length < 1024) { // Less than 1KB
                console.warn("Image file too small, might be corrupted");
                showCorruptionWarning(inputElement, "Image file is unusually small", "LSB");
                return;
            }
            
            if (byteArray.length > 10 * 1024 * 1024) { // More than 10MB
                console.warn("Image file very large, might cause processing issues");
                showCorruptionWarning(inputElement, "Image file is very large (>10MB), might cause processing issues", "LSB");
            }
            
            // 4. Check for additional corruption patterns specifically seen with PVD/DCT
            // Look for repeating patterns that shouldn't be in valid images
            let repeatingBlocks = 0;
            for (let i = 0; i < Math.min(byteArray.length - 32, 5000); i += 16) {
                if (byteArray[i] === byteArray[i+16] && 
                    byteArray[i+1] === byteArray[i+17] &&
                    byteArray[i+2] === byteArray[i+18] &&
                    byteArray[i+3] === byteArray[i+19]) {
                    repeatingBlocks++;
                }
            }
            
            if (repeatingBlocks > 50) { // High number of repeating blocks
                console.warn(`Detected ${repeatingBlocks} repeating blocks, potential corruption`);
                showCorruptionWarning(inputElement, "Image may have corrupted data structure", "LSB");
                return;
            }
            
            // If we get here, the image file appears valid
            console.log("Image passes basic corruption checks");
            
            // Create an actual image object to check loading
            const img = new Image();
            img.onload = function() {
                console.log(`Image loaded successfully: ${img.width}x${img.height}`);
                
                // Check for very small dimensions
                if (img.width < 50 || img.height < 50) {
                    showCorruptionWarning(inputElement, "Image dimensions are very small", "LSB");
                }
                
                // Set recommended method based on file size and properties
                let recommendedMethod = "LSB"; // Default to LSB
                if (file.size > 500000) { // Larger than 500KB
                    // For larger images, LSB is still most reliable
                    recommendedMethod = "LSB";
                }
                
                // Update UI with information
                const methodSelector = document.querySelector('select[name="encryption_method"]');
                if (methodSelector) {
                    methodSelector.value = recommendedMethod;
                    
                    // Trigger change event
                    const event = new Event('change');
                    methodSelector.dispatchEvent(event);
                    
                    // Add info text
                    const container = methodSelector.closest('.form-group, .mb-3');
                    if (container) {
                        let infoElement = container.querySelector('.method-recommendation');
                        if (!infoElement) {
                            infoElement = document.createElement('small');
                            infoElement.className = 'form-text text-muted method-recommendation';
                            container.appendChild(infoElement);
                        }
                        infoElement.textContent = `Recommended method for this image: ${recommendedMethod}`;
                    }
                }
            };
            
            img.onerror = function() {
                console.error("Error loading image - likely corrupted");
                showCorruptionWarning(inputElement, "Error loading image - file may be corrupted", "LSB");
            };
            
            // Set src to a data URL of the file
            img.src = URL.createObjectURL(file);
        };
        
        reader.onerror = function() {
            console.error("Error reading file");
            showCorruptionWarning(inputElement, "Error reading file - may be corrupted", "LSB");
        };
        
        // Start reading the file
        reader.readAsArrayBuffer(file);
    }
    
    // Function to display a warning about potential corruption
    function showCorruptionWarning(inputElement, message, recommendedMethod) {
        // Find closest container
        const container = inputElement.closest('.mb-3, .form-group');
        if (!container) return;
        
        // Create warning element
        const warning = document.createElement('div');
        warning.className = 'alert alert-warning mt-2 corruption-warning';
        warning.innerHTML = `
            <strong>Warning:</strong> ${message}
            <div class="mt-1">
                <small>Recommendation: Use <strong>${recommendedMethod}</strong> method for decryption</small>
            </div>
        `;
        
        // Remove any existing warnings
        const existingWarning = container.querySelector('.corruption-warning');
        if (existingWarning) {
            existingWarning.remove();
        }
        
        // Add the warning after the input
        inputElement.parentNode.appendChild(warning);
        
        // If there's a method selector, set it to the recommended value
        const methodSelector = document.querySelector('select[name="encryption_method"]');
        if (methodSelector && recommendedMethod) {
            methodSelector.value = recommendedMethod;
            
            // Trigger change event
            const event = new Event('change');
            methodSelector.dispatchEvent(event);
        }
    }
    
    // Add direct fallback option for heavily corrupted images
    function addFallbackOption() {
        const decryptForm = document.getElementById('decrypt-form');
        const methodSelector = document.querySelector('select[name="encryption_method"]');
        
        if (decryptForm && methodSelector) {
            // Add a fallback button that bypasses method selection
            const submitButton = decryptForm.querySelector('button[type="submit"]');
            if (submitButton) {
                const fallbackButton = document.createElement('button');
                fallbackButton.type = 'button';
                fallbackButton.className = 'btn btn-outline-secondary ms-2';
                fallbackButton.id = 'fallback-decrypt-btn';
                fallbackButton.innerHTML = '<i class="bi bi-tools"></i> Try Direct LSB';
                
                // Insert after submit button
                submitButton.parentNode.insertBefore(fallbackButton, submitButton.nextSibling);
                
                // Add click handler for the fallback button
                fallbackButton.addEventListener('click', function() {
                    // Force LSB method
                    methodSelector.value = 'LSB';
                    
                    // Indicate we're using direct LSB
                    const hiddenInput = document.createElement('input');
                    hiddenInput.type = 'hidden';
                    hiddenInput.name = 'force_direct_lsb';
                    hiddenInput.value = 'true';
                    decryptForm.appendChild(hiddenInput);
                    
                    // Submit the form
                    const submitEvent = new Event('submit', { cancelable: true });
                    decryptForm.dispatchEvent(submitEvent);
                    
                    // Remove the hidden input after submission
                    setTimeout(() => {
                        decryptForm.removeChild(hiddenInput);
                    }, 100);
                });
            }
        }
    }
    
    // On decrypt modal show, apply the fixes
    const decryptModal = document.getElementById('decryptModal');
    if (decryptModal) {
        decryptModal.addEventListener('show.bs.modal', function() {
            // Set default method to LSB since that's most reliable
            const methodSelector = document.querySelector('select[name="encryption_method"]');
            if (methodSelector) {
                methodSelector.value = 'LSB';
                
                // Trigger change event
                const event = new Event('change');
                methodSelector.dispatchEvent(event);
            }
            
            // Add fallback option
            addFallbackOption();
        });
    }
    
    // Add direct fallback API support
    function setupFallbackAPI() {
        // This function will be called when standard decryption fails
        window.tryFallbackDecryption = function(imageId, password) {
            console.log("Attempting fallback decryption with direct LSB");
            
            // Get CSRF token from meta tag
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
            
            // Create form data
            const formData = new FormData();
            formData.append('image_id', imageId);
            formData.append('password', password);
            
            // Show loading indicator if available
            const loadingIndicator = document.getElementById('loading-indicator');
            if (loadingIndicator) loadingIndicator.style.display = 'block';
            
            // Call the fallback API endpoint
            fetch('/api/decrypt_fallback', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': csrfToken
                }
            })
            .then(response => response.json())
            .then(data => {
                // Hide loading indicator
                if (loadingIndicator) loadingIndicator.style.display = 'none';
                
                // Process response
                if (data.success && data.decrypted_message) {
                    // Show success message
                    console.log("Fallback decryption succeeded");
                    
                    // Display the message if we have the right elements
                    const resultContainer = document.getElementById('decryption-result');
                    const messageElement = document.getElementById('decrypted-message');
                    
                    if (resultContainer && messageElement) {
                        // Show result container
                        resultContainer.style.display = 'block';
                        
                        // Set message
                        messageElement.value = data.decrypted_message;
                        
                        // Hide form container
                        const formContainer = document.getElementById('decrypt-form-container');
                        if (formContainer) formContainer.style.display = 'none';
                        
                        // Hide submit button
                        const submitBtn = document.getElementById('decrypt-submit-btn');
                        if (submitBtn) submitBtn.style.display = 'none';
                    } else {
                        // Just alert if we don't have the right elements
                        alert("Decryption successful: " + data.decrypted_message);
                    }
                } else {
                    // Show error
                    console.error("Fallback decryption failed:", data.message);
                    alert("Fallback decryption failed: " + (data.message || "Unknown error"));
                }
            })
            .catch(error => {
                console.error("Fallback API error:", error);
                alert("Error during fallback decryption attempt");
                
                // Hide loading indicator
                if (loadingIndicator) loadingIndicator.style.display = 'none';
            });
        }
    }
    
    // Initialize fallback API support
    setupFallbackAPI();
});
