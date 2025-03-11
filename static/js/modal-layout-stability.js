/**
 * Modal Layout Stability Fix
 * Ensures dashboard layout remains completely stable when modal is open
 * Prevents any layout destruction or shifting
 */

document.addEventListener('DOMContentLoaded', function() {
    // CRITICAL: Save original layout state to restore later
    const originalLayoutState = {};

    // Watch for modal open events
    document.body.addEventListener('show.bs.modal', function(event) {
        console.log('Modal opening, preserving layout state');
        
        // Store the current layout metrics
        storeLayoutMetrics();

        // Apply immediate layout preservation
        forceLayoutStability();
    }, true);

    // Apply fixes when modal is fully shown
    document.body.addEventListener('shown.bs.modal', function(event) {
        console.log('Modal open, ensuring layout stability');
        
        // Reapply layout preservation after modal fully opens
        forceLayoutStability();
    }, true);

    // Restore original layout when modal closes
    document.body.addEventListener('hidden.bs.modal', function(event) {
        console.log('Modal closed, restoring layout');
        
        // Clean up our enforced styles
        document.body.classList.remove('layout-locked');
        
        // Force redraw to restore layout
        setTimeout(function() {
            window.dispatchEvent(new Event('resize'));
        }, 50);
    });

    // Store key layout metrics for restoration
    function storeLayoutMetrics() {
        // Store main layout container metrics
        const container = document.querySelector('.container');
        if (container) {
            originalLayoutState.containerWidth = container.offsetWidth;
            originalLayoutState.containerDisplay = window.getComputedStyle(container).display;
        }

        // Store row metrics
        document.querySelectorAll('.row').forEach((row, index) => {
            originalLayoutState[`row_${index}`] = {
                width: row.offsetWidth,
                display: window.getComputedStyle(row).display
            };
        });

        // Store column metrics
        document.querySelectorAll('.col-md-4').forEach((col, index) => {
            originalLayoutState[`col_${index}`] = {
                width: col.offsetWidth,
                height: col.offsetHeight
            };
        });
    }

    // Force layout to stay stable
    function forceLayoutStability() {
        // Lock the body to prevent layout shifting
        document.body.classList.add('layout-locked');
        
        // Force proper display modes on critical layout elements
        document.querySelectorAll('.row').forEach(row => {
            row.style.display = 'flex';
            row.style.flexWrap = 'wrap';
        });
        
        // Ensure columns maintain proper sizing
        document.querySelectorAll('.col-md-4').forEach(col => {
            col.style.flex = '0 0 33.333%';
            col.style.maxWidth = '33.333%';
            col.style.display = 'block';
        });
        
        // Ensure cards maintain proper structure
        document.querySelectorAll('.card').forEach(card => {
            card.style.display = 'flex';
            card.style.flexDirection = 'column';
            card.style.height = '100%';
        });
    }

    // Add a global resize event listener to maintain layout during window changes
    window.addEventListener('resize', function() {
        // If a modal is open, reapply our layout stability
        if (document.body.classList.contains('modal-open')) {
            requestAnimationFrame(forceLayoutStability);
        }
    });
});
