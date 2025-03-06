document.addEventListener('DOMContentLoaded', function() {
    // Get the encryption form
    const encryptForm = document.getElementById('encrypt-form');
    if (!encryptForm) return;
    
    // Log form found for debugging
    console.log('Encryption form found, attaching handlers');
    
    // Handle form submission
    encryptForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        console.log('Encryption form submitted');
        
        // Show loading state
        const submitButton = encryptForm.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
        submitButton.disabled = true;
        
        // Get form data
        const formData = new FormData(encryptForm);
        
        // Simple validation
        const image = formData.get('image');
        const message = formData.get('message');
        const password = formData.get('password');
        
        let hasError = false;
        let errorMessage = '';
        
        if (!image || image.size === 0) {
            hasError = true;
            errorMessage = 'Please select an image file';
        } else if (!message) {
            hasError = true;
            errorMessage = 'Please enter a message to hide';
        } else if (!password) {
            hasError = true;
            errorMessage = 'Please enter an encryption password';
        }
        
        if (hasError) {
            submitButton.innerHTML = originalButtonText;
            submitButton.disabled = false;
            showAlert(errorMessage, 'danger');
            return;
        }
        
        // Get CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        
        // Send AJAX request
        fetch('/encrypt', {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRFToken': csrfToken
            }
        })
        .then(response => {
            console.log('Encryption response received');
            if (!response.ok) {
                throw new Error(`Server responded with ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Encryption response data:', data);
            if (data.success) {
                showAlert(data.message || 'Encryption successful!', 'success');
                setTimeout(() => {
                    window.location.href = data.redirect || '/dashboard';
                }, 1500);
            } else {
                throw new Error(data.message || 'Unknown error occurred');
            }
        })
        .catch(error => {
            console.error('Encryption error:', error);
            showAlert(`Error: ${error.message}`, 'danger');
            submitButton.innerHTML = originalButtonText;
            submitButton.disabled = false;
        });
    });
    
    // Function to show alert messages
    function showAlert(message, type) {
        const alertContainer = document.querySelector('.alert-container');
        if (!alertContainer) {
            // Create alert container if it doesn't exist
            const container = document.querySelector('.container');
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert-container';
            container.insertBefore(alertDiv, container.firstChild);
        }
        
        // Create alert
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Add to page
        document.querySelector('.alert-container').appendChild(alert);
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            alert.classList.remove('show');
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    }
    
    // Add progress tracking handling to the form submission
    const form = document.getElementById('encryptForm');
    const progressBar = document.getElementById('progressBar');
    const progressContainer = document.getElementById('progressContainer');
    const btnSubmit = document.getElementById('btnSubmit');
    const loadingText = document.getElementById('loadingText');
    
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get the message length to determine if it's a large message
            const message = document.getElementById('message').value;
            const isLargeMessage = message.length > 10000; // Consider messages over 10KB as large
            
            // Show progress bar for large messages
            if (isLargeMessage) {
                progressContainer.style.display = 'block';
                progressBar.style.width = '0%';
                progressBar.setAttribute('aria-valuenow', 0);
                loadingText.innerText = 'Preparing to encode large message...';
            }
            
            btnSubmit.disabled = true;
            btnSubmit.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
            
            // Create form data including CSRF token
            const formData = new FormData(form);
            
            // Send AJAX request
            const xhr = new XMLHttpRequest();
            xhr.open('POST', form.action);
            
            // Set up progress tracking for large messages
            if (isLargeMessage) {
                // Use progress event if available
                xhr.upload.onprogress = function(e) {
                    if (e.lengthComputable) {
                        const percentComplete = (e.loaded / e.total) * 100;
                        updateProgress(percentComplete);
                    }
                };
                
                // Also listen for custom progress events from the server
                const eventSource = new EventSource('/progress');
                eventSource.onmessage = function(e) {
                    const data = JSON.parse(e.data);
                    if (data.task === 'encode' && data.progress) {
                        updateProgress(data.progress);
                    }
                };
                
                eventSource.onerror = function() {
                    eventSource.close();
                };
            }
            
            xhr.onload = function() {
                if (isLargeMessage) {
                    updateProgress(100);
                }
                
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response.success) {
                        showAlert('success', response.message);
                        // Redirect after short delay
                        setTimeout(function() {
                            window.location.href = response.redirect;
                        }, 1500);
                    } else {
                        showAlert('danger', response.message);
                        btnSubmit.disabled = false;
                        btnSubmit.innerHTML = 'Encrypt & Hide Message';
                    }
                } catch (e) {
                    showAlert('danger', 'An error occurred processing the response');
                    btnSubmit.disabled = false;
                    btnSubmit.innerHTML = 'Encrypt & Hide Message';
                }
            };
            
            xhr.onerror = function() {
                showAlert('danger', 'Request failed. Please try again.');
                btnSubmit.disabled = false;
                btnSubmit.innerHTML = 'Encrypt & Hide Message';
            };
            
            xhr.send(formData);
        });
    }
    
    // Function to update progress bar
    function updateProgress(percent) {
        const roundedPercent = Math.round(percent);
        progressBar.style.width = roundedPercent + '%';
        progressBar.setAttribute('aria-valuenow', roundedPercent);
        
        if (roundedPercent < 30) {
            loadingText.innerText = 'Encoding message...';
        } else if (roundedPercent < 70) {
            loadingText.innerText = 'Applying steganography...';
        } else {
            loadingText.innerText = 'Finalizing image...';
        }
        
        if (roundedPercent === 100) {
            loadingText.innerText = 'Done! Redirecting...';
        }
    }
    
    // Function to show alerts
    function showAlert(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        const alertContainer = document.getElementById('alertContainer');
        alertContainer.innerHTML = '';
        alertContainer.appendChild(alertDiv);
        alertContainer.scrollIntoView({ behavior: 'smooth' });
    }

    // Capacity Estimator
    const imageInput = document.getElementById('image');
    const messageInput = document.getElementById('message');
    const methodSelect = document.getElementById('encryption_method');
    const loadingIndicator = document.getElementById('loading-indicator');
    const capacityIndicator = document.getElementById('capacity-indicator');
    const noImageText = document.getElementById('no-image-selected');
    const capacityProgress = document.getElementById('capacity-progress');
    const capacityText = document.getElementById('capacity-text');
    const encryptionProgress = document.getElementById('encryption-progress');
    
    let imageCapacity = 0;
    let selectedFile = null;
    
    // Handle image file selection
    imageInput.addEventListener('change', function(e) {
        if (this.files && this.files[0]) {
            selectedFile = this.files[0];
            getImageCapacity(this.files[0], methodSelect.value);
        } else {
            resetCapacityIndicator();
        }
    });
    
    // Handle method change
    methodSelect.addEventListener('change', function() {
        if (selectedFile) {
            getImageCapacity(selectedFile, this.value);
        }
    });
    
    // Handle message input to update capacity indicator
    messageInput.addEventListener('input', function() {
        updateCapacityUsage();
    });
    
    // Fetch image capacity from server
    function getImageCapacity(file, method) {
        const formData = new FormData();
        formData.append('image', file);
        formData.append('method', method);
        
        fetch('/api/estimate_capacity', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                imageCapacity = data.capacity_bytes;
                capacityIndicator.classList.remove('d-none');
                noImageText.classList.add('d-none');
                updateCapacityUsage();
            } else {
                console.error('Capacity estimation failed:', data.message);
                resetCapacityIndicator();
            }
        })
        .catch(error => {
            console.error('Error estimating capacity:', error);
            resetCapacityIndicator();
        });
    }
    
    // Update capacity usage based on message length
    function updateCapacityUsage() {
        if (imageCapacity > 0) {
            const messageBytes = new Blob([messageInput.value]).size;
            const percentUsed = Math.min(100, Math.round((messageBytes / imageCapacity) * 100));
            
            capacityProgress.style.width = percentUsed + '%';
            capacityText.textContent = `${messageBytes} / ${imageCapacity} bytes`;
            
            // Change progress bar color based on usage
            if (percentUsed > 90) {
                capacityProgress.className = 'progress-bar bg-danger';
            } else if (percentUsed > 70) {
                capacityProgress.className = 'progress-bar bg-warning';
            } else {
                capacityProgress.className = 'progress-bar bg-success';
            }
        }
    }
    
    // Reset capacity indicator to default state
    function resetCapacityIndicator() {
        imageCapacity = 0;
        capacityIndicator.classList.add('d-none');
        noImageText.classList.remove('d-none');
    }
    
    // Handle form submission
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Validate capacity
        if (imageCapacity > 0) {
            const messageBytes = new Blob([messageInput.value]).size;
            if (messageBytes > imageCapacity) {
                alert('Message is too large for this image with the selected method. Please choose a larger image or different method.');
                return;
            }
        }
        
        // Show loading indicator
        form.style.display = 'none';
        loadingIndicator.style.display = 'block';
        
        // Create form data
        const formData = new FormData(form);
        
        // Start progress updates (could be connected to a WebSocket in a real implementation)
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += 5;
            if (progress > 95) clearInterval(progressInterval);
            encryptionProgress.style.width = progress + '%';
        }, 200);
        
        // Submit form
        fetch('/encrypt', {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            clearInterval(progressInterval);
            encryptionProgress.style.width = '100%';
            
            if (data.success) {
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 500);
            } else {
                alert('Error: ' + data.message);
                form.style.display = 'block';
                loadingIndicator.style.display = 'none';
            }
        })
        .catch(error => {
            clearInterval(progressInterval);
            console.error('Error:', error);
            alert('An error occurred. Please try again.');
            form.style.display = 'block';
            loadingIndicator.style.display = 'none';
        });
    });
});
