/**
 * Encryption method utilities for SteganoSafe
 * 
 * This script provides helper functions and initialization for the encryption method selector
 */

// Initialize encryption methods when document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Try to get encryption method selectors
    const encryptionMethodSelectors = document.querySelectorAll('select[name="encryption_method"]');
    
    if (encryptionMethodSelectors.length > 0) {
        console.log(`Found ${encryptionMethodSelectors.length} encryption method selectors`);
        
        // Add tooltips for each method
        const tooltips = {
            'LSB': 'Least Significant Bit - Fast with decent capacity, less resistant to image modifications',
            'PVD': 'Pixel Value Differencing - Better security and slightly higher capacity than LSB',
            'DCT': 'Discrete Cosine Transform - More resistant to image compression, but slower',
            'DWT': 'Discrete Wavelet Transform - Advanced method with good resistance to detection'
        };
        
        // Initialize each selector
        encryptionMethodSelectors.forEach(selector => {
            // Check if there are existing options
            if (selector.options.length === 0) {
                // Add default options
                for (const [method, description] of Object.entries(tooltips)) {
                    const option = document.createElement('option');
                    option.value = method;
                    option.text = method;
                    option.title = description;
                    if (method === 'LSB') {
                        option.selected = true;
                    }
                    selector.appendChild(option);
                }
            } else {
                // Just add tooltips to existing options
                for (let i = 0; i < selector.options.length; i++) {
                    const option = selector.options[i];
                    if (tooltips[option.value]) {
                        option.title = tooltips[option.value];
                    }
                }
            }
            
            // Add change event to show tooltip
            selector.addEventListener('change', function() {
                const selectedMethod = this.value;
                if (tooltips[selectedMethod]) {
                    const helpTextElement = this.nextElementSibling;
                    if (helpTextElement && helpTextElement.classList.contains('form-text')) {
                        helpTextElement.textContent = tooltips[selectedMethod];
                    }
                }
            });
        });
    }
    
    // Add helper functions to global scope
    window.StegUtils = {
        // Method to get capacity estimate for various encryption methods
        getCapacityEstimate: function(imageElement, method) {
            // Default capacities based on image dimensions (very rough estimates)
            const width = imageElement.naturalWidth;
            const height = imageElement.naturalHeight;
            const pixelCount = width * height;
            
            let bytesPerPixel;
            
            switch (method) {
                case 'LSB': 
                    bytesPerPixel = 0.125; // 1 bit per channel, 3 channels
                    break;
                case 'PVD':
                    bytesPerPixel = 0.25; // Roughly double LSB in ideal conditions
                    break;
                case 'DCT':
                    bytesPerPixel = 0.0625; // Roughly half of LSB
                    break;
                case 'DWT':
                    bytesPerPixel = 0.09375; // Roughly 3/4 of LSB
                    break;
                default:
                    bytesPerPixel = 0.125; // Default to LSB
            }
            
            // Calculate capacity and convert to appropriate unit
            const capacityBytes = Math.floor(pixelCount * bytesPerPixel);
            
            if (capacityBytes < 1024) {
                return capacityBytes + ' bytes';
            } else if (capacityBytes < 1024 * 1024) {
                return Math.floor(capacityBytes / 1024 * 10) / 10 + ' KB';
            } else {
                return Math.floor(capacityBytes / (1024 * 1024) * 10) / 10 + ' MB';
            }
        }
    };
});

/**
 * Encryption Method Fix
 * 
 * This file handles specific fixes related to encryption method selection
 * and provides consistent behavior across all pages.
 */

document.addEventListener('DOMContentLoaded', function() {
    console.log("Encryption method fix initialized");
    
    // Fix dropdown selection behavior for encryption methods
    const methodSelectors = document.querySelectorAll('select[name="encryption_method"]');
    methodSelectors.forEach(select => {
        // Ensure native dropdown behavior
        select.classList.add('native-select');
        
        // Store original selected value
        const originalValue = select.value;
        
        // Force redraw to ensure dropdown works correctly
        select.style.display = 'none';
        setTimeout(() => {
            select.style.display = '';
            select.value = originalValue; // Restore selection
        }, 10);
        
        // Handle change events
        select.addEventListener('change', function() {
            const selectedMethod = this.value;
            console.log(`Encryption method changed to: ${selectedMethod}`);
            
            // Get any associated info elements
            const container = this.closest('.form-group, .mb-3');
            if (container) {
                const infoElement = container.querySelector('.encryption-method-info');
                if (infoElement) {
                    // Update info based on selected method
                    switch(selectedMethod) {
                        case 'LSB':
                            infoElement.textContent = 'LSB: Standard method with good balance of capacity and security';
                            break;
                        case 'PVD':
                            infoElement.textContent = 'PVD: Improved resistance to detection';
                            break;
                        case 'DCT':
                            infoElement.textContent = 'DCT: Higher security, uses frequency domain embedding';
                            break;
                        case 'DWT':
                            infoElement.textContent = 'DWT: Advanced method with good robustness';
                            break;
                        case 'AUTO':
                            infoElement.textContent = 'Auto: Tries all methods to find the embedded message';
                            break;
                        default:
                            infoElement.textContent = '';
                    }
                }
            }
        });
    });
    
    // Fix decryption method selector in modals
    const decryptModal = document.getElementById('decryptModal');
    if (decryptModal) {
        decryptModal.addEventListener('shown.bs.modal', function() {
            const methodSelector = this.querySelector('select[name="encryption_method"]');
            if (methodSelector) {
                // Ensure dropdown works in modal context
                setTimeout(() => {
                    methodSelector.style.display = 'none';
                    setTimeout(() => {
                        methodSelector.style.display = '';
                    }, 10);
                }, 50);
            }
        });
    }
});

document.addEventListener('DOMContentLoaded', function() {
    console.log("Encryption method handler initialized");
    
    // Find encryption method selector
    const methodSelector = document.querySelector('select[name="encryption_method"]');
    if (!methodSelector) {
        console.warn("Encryption method selector not found in the page");
        return;
    }
    
    // Add event listener to method selector
    methodSelector.addEventListener('change', function() {
        const selectedMethod = this.value;
        console.log(`Selected encryption method: ${selectedMethod}`);
        
        // Update method info display
        updateMethodInfo(selectedMethod);
        
        // If we're in the encrypt form page, verify method compatibility
        if (document.getElementById('encrypt-form')) {
            checkMethodCompatibility(selectedMethod);
        }
    });
    
    // Initialize with current selection
    if (methodSelector.value) {
        updateMethodInfo(methodSelector.value);
    }
    
    // Function to update method info display
    function updateMethodInfo(method) {
        const infoText = document.querySelector('.encryption-method-info') || 
                        document.querySelector('.form-text');
        
        if (!infoText) return;
        
        // Update info based on selected method
        switch (method.toUpperCase()) {
            case 'LSB':
                infoText.innerHTML = '<strong>LSB:</strong> Least Significant Bit - Fast and simple encoding with good capacity.';
                break;
            case 'PVD':
                infoText.innerHTML = '<strong>PVD:</strong> Pixel Value Differencing - Better security with slightly lower capacity.';
                break;
            case 'DCT':
                infoText.innerHTML = '<strong>DCT:</strong> Discrete Cosine Transform - More resistant to image modifications.';
                break;
            case 'DWT':
                infoText.innerHTML = '<strong>DWT:</strong> Discrete Wavelet Transform - Advanced method with good stealth properties.';
                break;
            case 'AUTO':
                infoText.innerHTML = '<strong>AUTO:</strong> Try all available methods to find the message automatically.';
                break;
            default:
                infoText.innerHTML = 'Select a steganography method.';
        }
    }
    
    // Function to check method compatibility with selected image
    function checkMethodCompatibility(method) {
        const imageInput = document.getElementById('image');
        if (!imageInput || !imageInput.files || !imageInput.files[0]) return;
        
        const file = imageInput.files[0];
        const fileSize = file.size;
        
        // Show warning for large files with complex methods
        if (fileSize > 2 * 1024 * 1024 && (method === 'DCT' || method === 'DWT')) {
            showMethodWarning(`Large image (${Math.round(fileSize/1024/1024)}MB) may process slowly with ${method} method.`);
        } else {
            // Remove any existing warning
            const existingWarning = document.querySelector('.method-warning');
            if (existingWarning) existingWarning.remove();
        }
    }
    
    // Function to display method warnings
    function showMethodWarning(message) {
        // Remove any existing warning
        const existingWarning = document.querySelector('.method-warning');
        if (existingWarning) existingWarning.remove();
        
        // Find container to add warning to
        const container = methodSelector.closest('.mb-3, .form-group');
        if (!container) return;
        
        // Create warning element
        const warning = document.createElement('div');
        warning.className = 'alert alert-warning mt-2 method-warning';
        warning.style.fontSize = '0.875rem';
        warning.innerHTML = message;
        
        // Add to container
        container.appendChild(warning);
    }
});