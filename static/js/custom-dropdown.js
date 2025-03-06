/**
 * Replace problematic select dropdown with custom implementation
 */
document.addEventListener('DOMContentLoaded', function() {
    // Find all select elements
    document.querySelectorAll('select.form-select').forEach(select => {
        // Don't process already handled selects
        if (select.dataset.replaced === 'true') return;
        
        console.log(`Creating custom dropdown for: ${select.id || 'unnamed select'}`);
        
        // Create a wrapper element
        const wrapper = document.createElement('div');
        wrapper.className = 'custom-dropdown-wrapper position-relative';
        
        // Create the custom dropdown button
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'form-select text-start d-flex justify-content-between align-items-center';
        button.style.width = '100%';
        
        // Add selected option text to button
        const selectedOption = select.options[select.selectedIndex];
        button.innerHTML = `
            <span>${selectedOption ? selectedOption.text : 'Select'}</span>
            <i class="bi bi-chevron-down"></i>
        `;
        
        // Create the dropdown menu
        const dropdownMenu = document.createElement('div');
        dropdownMenu.className = 'dropdown-menu w-100';
        dropdownMenu.style.display = 'none';
        
        // Add options to the dropdown menu
        Array.from(select.options).forEach(option => {
            const item = document.createElement('a');
            item.className = 'dropdown-item';
            item.href = '#';
            item.textContent = option.text;
            item.dataset.value = option.value;
            
            item.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Update the original select
                select.value = this.dataset.value;
                
                // Update button text
                button.querySelector('span').textContent = this.textContent;
                
                // Hide dropdown
                dropdownMenu.style.display = 'none';
                
                // Trigger change event on original select
                const event = new Event('change', { bubbles: true });
                select.dispatchEvent(event);
            });
            
            dropdownMenu.appendChild(item);
        });
        
        // Toggle dropdown on button click
        button.addEventListener('click', function(e) {
            e.stopPropagation();
            
            const isVisible = dropdownMenu.style.display === 'block';
            dropdownMenu.style.display = isVisible ? 'none' : 'block';
        });
        
        // Hide dropdown when clicking outside
        document.addEventListener('click', function() {
            dropdownMenu.style.display = 'none';
        });
        
        // Prevent clicks inside the dropdown from closing it
        dropdownMenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });
        
        // Add elements to the wrapper
        wrapper.appendChild(button);
        wrapper.appendChild(dropdownMenu);
        
        // Hide the original select but keep it in the DOM for form submission
        select.style.display = 'none';
        select.dataset.replaced = 'true';
        
        // Insert the wrapper after the select element
        select.parentNode.insertBefore(wrapper, select.nextSibling);
    });
});
