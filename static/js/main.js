document.addEventListener('DOMContentLoaded', function () {
    // Generalized form handling function
    function handleFormSubmit(form, successCallback) {
        if (!form) return;
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            const formData = new FormData(this);

            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

            fetch(this.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRF-Token': csrfToken
                }
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        successCallback(data);
                    } else {
                        throw new Error(data.message || 'Unexpected Error');
                    }
                })
                .catch(error => {
                    Swal.fire({
                        icon: 'error',
                        title: 'Error',
                        text: error.message || 'An unexpected error occurred.'
                    });
                });

        });
    }

    // Success callbacks for specific forms
    function handleEncryptionSuccess(data) {
        Swal.fire({
            icon: 'success',
            title: 'Success',
            text: data.message
        }).then(() => {
            if (data.download_url) {
                window.location.href = data.download_url;
            }
            window.location.reload();
        });
    }

    function handleDecryptionSuccess(data) {
        const decryptResult = document.getElementById('decryptResult');
        const decryptedMessage = document.getElementById('decryptedMessage');
        if (decryptResult && decryptedMessage) {
            decryptedMessage.textContent = data.message;
            decryptResult.classList.remove('d-none');
            decryptResult.scrollIntoView({ behavior: 'smooth' });
        }
    }

    function handleRedirectSuccess(data) {
        window.location.href = data.redirect;
    }

    // Attach handlers to forms
    handleFormSubmit(document.getElementById('encryptForm'), handleEncryptionSuccess);
    handleFormSubmit(document.getElementById('decryptForm'), handleDecryptionSuccess);
    handleFormSubmit(document.querySelector('form[action*="login"]'), handleRedirectSuccess);
    handleFormSubmit(document.querySelector('form[action*="register"]'), function (data) {
        Swal.fire({
            icon: 'success',
            title: 'Success',
            text: 'Registration successful!'
        }).then(() => {
            window.location.href = data.redirect;
        });
    });

    // File input validation
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.addEventListener('change', function () {
            const file = this.files[0];
            const maxSize = 16 * 1024 * 1024; // 16MB
            if (file && file.size > maxSize) {
                this.value = '';
                Swal.fire({
                    icon: 'error',
                    title: 'File Too Large',
                    text: 'Please select an image under 16MB.'
                });
            }
        });
    });

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Auto-dismiss alerts after 5 seconds
    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});

