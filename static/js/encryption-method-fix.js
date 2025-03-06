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