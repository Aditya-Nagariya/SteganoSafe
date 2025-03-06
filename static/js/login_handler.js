document.addEventListener('DOMContentLoaded', function() {
    console.log('Login handler script loaded');
    
    // Handle login form submission
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Logging in...';
            
            // Get CSRF token
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            
            // Send AJAX request
            fetch('/login', {
                method: 'POST',
                body: new FormData(this),
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'same-origin'
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || 'Login failed');
                    });
                }
                return response.json();
            })
            .then(data => {
                console.log('Login response:', data);
                
                if (data.success) {
                    // Display success message
                    if (typeof Swal !== 'undefined') {
                        Swal.fire({
                            icon: 'success',
                            title: 'Success!',
                            text: 'Login successful. Redirecting...',
                            timer: 1500,
                            showConfirmButton: false
                        });
                    }
                    
                    // First verify session is established before redirecting
                    verifyAndRedirect(data.redirect || '/dashboard');
                } else {
                    // Reset button
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                    
                    // Show error message
                    if (typeof Swal !== 'undefined') {
                        Swal.fire({
                            icon: 'error',
                            title: 'Login Failed',
                            text: data.message || 'Invalid username or password'
                        });
                    } else {
                        alert('Login failed: ' + (data.message || 'Invalid username or password'));
                    }
                }
            })
            .catch(error => {
                console.error('Login error:', error);
                
                // Reset button
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
                
                // Show error message
                if (typeof Swal !== 'undefined') {
                    Swal.fire({
                        icon: 'error',
                        title: 'Login Error',
                        text: error.message || 'An error occurred during login'
                    });
                } else {
                    alert('Login error: ' + (error.message || 'An error occurred'));
                }
            });
        });
    }
    
    // Function to verify session establishment before redirecting
    function verifyAndRedirect(url) {
        // Check if session is established
        fetch('/check-session', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            console.log('Session check:', data);
            
            if (data.authenticated) {
                // Session is established, redirect safely
                console.log('Session verified, redirecting to:', url);
                window.location.href = url;
            } else {
                // Session not established, use form submission as fallback
                console.log('Session not established, using fallback');
                if (document.getElementById('direct-login-form')) {
                    document.getElementById('direct-login-form').submit();
                } else {
                    // Last resort - reload page
                    window.location.reload();
                }
            }
        })
        .catch(error => {
            console.error('Session check error:', error);
            // Fallback to direct redirect
            window.location.href = url;
        });
    }
});
