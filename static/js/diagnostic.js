/**
 * Diagnostic script to help identify dropdown issues
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log("---- DIAGNOSTIC INFORMATION ----");

    // Check if the encryption method dropdown exists
    const dropdown = document.getElementById('encryption_method');
    console.log("Encryption method dropdown found:", !!dropdown);

    if (dropdown) {
        // Check how many options it has
        console.log("Number of options:", dropdown.options.length);
        
        // List all options
        console.log("Available options:");
        Array.from(dropdown.options).forEach((opt, index) => {
            console.log(`Option ${index}: ${opt.value} - ${opt.text}`);
        });
        
        // Check if it's visible
        const style = window.getComputedStyle(dropdown);
        console.log("Dropdown style:", {
            display: style.display,
            visibility: style.visibility,
            opacity: style.opacity,
            position: style.position,
            zIndex: style.zIndex
        });
    }
    
    // Check for any JavaScript errors
    const errors = [];
    window.onerror = function(message, source, lineno, colno, error) {
        errors.push({message, source, lineno, colno});
        console.error("JavaScript error:", message, source, lineno);
    };
    
    console.log("---- END DIAGNOSTIC INFORMATION ----");
});
