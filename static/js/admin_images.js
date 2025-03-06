/**
 * Admin Images Management JavaScript
 * Handles image loading, previews, and interactions
 */

// Initialize image preview functionality
function initImagePreviews() {
    const imagePreviews = document.querySelectorAll('.admin-images-table img');
    
    imagePreviews.forEach(img => {
        // Add loading state
        img.classList.add('loading');
        
        // Handle loading
        img.onload = function() {
            this.classList.remove('loading');
            this.classList.add('loaded');
        };
        
        // Handle errors
        img.onerror = function() {
            this.classList.remove('loading');
            this.classList.add('error');
            this.src = '/static/img/placeholder.png'; // Fallback to placeholder
            console.error(`Failed to load image: ${this.getAttribute('data-original-src')}`);
        };
        
        // Set click for zoom
        img.addEventListener('click', function(e) {
            // Toggle zoom class
            if (this.classList.contains('zoomed')) {
                this.classList.remove('zoomed');
            } else {
                // Remove zoomed class from any other images
                document.querySelectorAll('.admin-images-table img.zoomed').forEach(el => {
                    el.classList.remove('zoomed');
                });
                
                this.classList.add('zoomed');
                
                // Prevent event propagation
                e.stopPropagation();
            }
        });
        
        // Add lazy loading
        if (!img.hasAttribute('src') && img.hasAttribute('data-src')) {
            img.src = img.getAttribute('data-src');
        }
    });
    
    // Click anywhere else to close zoomed image
    document.addEventListener('click', function() {
        document.querySelectorAll('.admin-images-table img.zoomed').forEach(img => {
            img.classList.remove('zoomed');
        });
    });
}

// Handle search functionality
function initImageSearch() {
    const searchInput = document.getElementById('image-search');
    
    if (searchInput) {
        searchInput.addEventListener('keyup', function(e) {
            // Submit search on Enter key
            if (e.key === 'Enter') {
                const searchForm = document.getElementById('image-search-form');
                if (searchForm) {
                    searchForm.submit();
                }
            }
        });
    }
}

// Create placeholder image if image loading fails
function createPlaceholderIfNeeded() {
    // Check if any images failed to load
    const failedImages = document.querySelectorAll('.admin-images-table img.error');
    
    if (failedImages.length > 0) {
        // Call API endpoint to ensure placeholder exists
        fetch('/admin/create_placeholder')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    console.log('Placeholder image available:', data.path);
                } else {
                    console.error('Failed to create placeholder:', data.error);
                }
            })
            .catch(error => {
                console.error('Error creating placeholder:', error);
            });
    }
}

// Initialize image preview lazy loading
function initLazyLoading() {
    if ('IntersectionObserver' in window) {
        const lazyImages = document.querySelectorAll('img[data-src]');
        
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.add('loading');
                    observer.unobserve(img);
                }
            });
        });
        
        lazyImages.forEach(img => {
            imageObserver.observe(img);
        });
    } else {
        // Fallback for browsers that don't support IntersectionObserver
        const lazyImages = document.querySelectorAll('img[data-src]');
        lazyImages.forEach(img => {
            img.src = img.dataset.src;
        });
    }
}

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Admin images initialized');
    initImagePreviews();
    initImageSearch();
    initLazyLoading();
    
    // Check for placeholder after a delay to handle loading issues
    setTimeout(createPlaceholderIfNeeded, 1000);
});

// Add functionality for image filtering
function filterImages(category) {
    const allImages = document.querySelectorAll('.image-row');
    
    allImages.forEach(img => {
        if (category === 'all' || img.getAttribute('data-category') === category) {
            img.style.display = '';
        } else {
            img.style.display = 'none';
        }
    });
    
    // Update active filter button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`.filter-btn[data-filter="${category}"]`).classList.add('active');
}
