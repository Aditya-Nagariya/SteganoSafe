document.addEventListener('DOMContentLoaded', function() {
    console.log("Dashboard fallback script loaded");
    
    // Handle the case where timestamp or created_at doesn't exist
    const fixDates = function() {
        const dateCells = document.querySelectorAll('.date-cell');
        dateCells.forEach(function(cell) {
            if (!cell) return;
            if (cell.textContent.includes('undefined') || cell.textContent.trim() === '') {
                cell.textContent = 'Unknown date';
                cell.classList.add('text-muted');
            }
        });
    };
    
    // Fix error when no images are found
    const fixEmptyImages = function() {
        const imagesTable = document.querySelector('#history-table, #images-table');
        const noImagesMsg = document.querySelector('#no-images-message');
        
        if (imagesTable && imagesTable.querySelector('tbody') && 
            imagesTable.querySelector('tbody').children.length === 0) {
            
            imagesTable.style.display = 'none';
            
            if (!noImagesMsg) {
                const container = document.querySelector('#images-container');
                if (container) {
                    const msgElement = document.createElement('div');
                    msgElement.id = 'no-images-message';
                    msgElement.className = 'text-center text-muted p-5';
                    msgElement.innerHTML = '<i class="bi bi-image" style="font-size: 3rem;"></i><p class="mt-3">You haven\'t created any encrypted images yet.</p>';
                    container.appendChild(msgElement);
                }
            } else if (noImagesMsg) {
                noImagesMsg.style.display = 'block';
            }
        }
    };
    
    // Execute fixes
    try {
        fixDates();
        fixEmptyImages();
    } catch (err) {
        console.error("Error in dashboard fallback script:", err);
    }
});
