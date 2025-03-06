
/**
 * Admin Image Filtering System
 * Dedicated script to handle image filtering in the admin panel
 */

// The main filtering function
function filterImagesBy(category) {
    console.log(`[Admin Filters] Filtering by: "${category}"`);
    
    // Normalize the category for comparison
    const categoryNormalized = (category || "").toLowerCase();
    
    // Find all image rows
    const imageRows = document.querySelectorAll('.image-row');
    console.log(`[Admin Filters] Found ${imageRows.length} image rows`);
    
    let visibleCount = 0;
    
    // Process each row
    imageRows.forEach(row => {
        // Get the row's category and normalize it
        let rowCategory = row.getAttribute('data-category');
        rowCategory = (rowCategory || "unknown").toLowerCase();
        
        // Decide visibility - show all for "all" category, otherwise match
        let isVisible = (categoryNormalized === 'all' || rowCategory === categoryNormalized);
        
        // Apply visibility
        row.style.display = isVisible ? "" : "none";
        
        // Count visible rows
        if (isVisible) visibleCount++;
        
        // Debug info
        console.log(`[Admin Filters] Image ID ${row.getAttribute('data-image-id')}: category=${rowCategory}, visible=${isVisible}`);
    });
    
    // Update button states
    document.querySelectorAll('.filter-btn').forEach(button => {
        const buttonCategory = button.getAttribute('data-filter');
        
        if (buttonCategory === category) {
            button.classList.add('active');
        } else {
            button.classList.remove('active');
        }
    });
    
    console.log(`[Admin Filters] Filter complete. Showing ${visibleCount} of ${imageRows.length} images.`);
    
    // Update the visible count display if it exists
    const countElement = document.getElementById("visible-count");
    if (countElement) {
        countElement.textContent = visibleCount;
    }
    
    return visibleCount;
}

// Make the function globally available
window.filterImages = filterImagesBy;

// Initialize everything when the document is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log("[Admin Filters] Initializing image filtering system");
    
    // 1. Add click handlers to all filter buttons
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(button => {
        // Store the button's filter value
        const filterValue = button.getAttribute('data-filter');
        
        // Add click handler
        button.addEventListener('click', function(event) {
            event.preventDefault();
            event.stopPropagation();
            console.log(`[Admin Filters] Filter button clicked: ${filterValue}`);
            filterImagesBy(filterValue);
        });
        
        console.log(`[Admin Filters] Added handler for ${filterValue} filter button`);
    });
    
    // 2. Apply the default filter (all)
    setTimeout(function() {
        filterImagesBy('all');
        console.log("[Admin Filters] Applied default 'all' filter");
    }, 100); // Small delay to ensure all DOM elements are ready
});
