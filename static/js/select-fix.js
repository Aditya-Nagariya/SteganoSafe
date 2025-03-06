/**
 * Force select elements to show dropdown options correctly
 */
document.addEventListener('DOMContentLoaded', function() {
    // Get all select elements with form-select class
    const selectElements = document.querySelectorAll('select.form-select');
    
    // Replace problematic selects with native HTML selects
    selectElements.forEach(select => {
        // Create a replacement select element
        const replacement = document.createElement('select');
        
        // Copy all attributes from the original select
        Array.from(select.attributes).forEach(attr => {
            replacement.setAttribute(attr.name, attr.value);
        });
        
        // Add native styling
        replacement.style.display = 'block';
        replacement.style.width = '100%';
        replacement.style.padding = '0.375rem 0.75rem';
        replacement.style.fontSize = '1rem';
        replacement.style.fontWeight = '400';
        replacement.style.lineHeight = '1.5';
        replacement.style.color = '#212529';
        replacement.style.backgroundColor = '#fff';
        replacement.style.backgroundClip = 'padding-box';
        replacement.style.border = '1px solid #ced4da';
        replacement.style.appearance = 'auto';
        replacement.style.borderRadius = '0.25rem';
        replacement.style.transition = 'border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out';
        
        // Copy all options from the original select
        Array.from(select.options).forEach(option => {
            const newOption = document.createElement('option');
            newOption.value = option.value;
            newOption.text = option.text;
            newOption.selected = option.selected;
            replacement.appendChild(newOption);
        });
        
        // Replace the original select with our new one
        select.parentNode.replaceChild(replacement, select);
        
        // Log for debugging
        console.log(`Fixed select element with ID: ${replacement.id || 'unnamed'}`);
    });
});

// Add a forced fix for the Bootstrap custom selects
function forceFixBootstrapSelects() {
    // Remove any custom styling that hides the dropdown arrow
    const style = document.createElement('style');
    style.textContent = `
        select.form-select, select.custom-select {
            -webkit-appearance: menulist !important;
            -moz-appearance: menulist !important;
            appearance: menulist !important;
            background-image: none !important;
        }
        
        /* Force dropdown to show above everything */
        select.form-select option, select.custom-select option {
            display: block !important;
            background-color: white !important;
            color: black !important;
        }
    `;
    
    document.head.appendChild(style);
    console.log("Applied forced select element fix");
}

// Apply the forced fix after a short delay to override any Bootstrap behaviors
setTimeout(forceFixBootstrapSelects, 500);
