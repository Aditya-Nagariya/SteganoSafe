/**
 * Utility functions for handling base64 encoding/decoding
 */

// Clean up base64 strings with potential errors
function cleanBase64String(str) {
    if (!str) return '';
    
    // Remove any non-base64 characters
    str = str.replace(/[^A-Za-z0-9+/=]/g, '');
    
    // Ensure proper padding
    while (str.length % 4 !== 0) {
        str += '=';
    }
    
    return str;
}

// Safe base64 encoding that handles errors
function safeBase64Encode(data) {
    try {
        if (typeof data === 'string') {
            // Convert to UTF-8 bytes first
            const encoder = new TextEncoder();
            const bytes = encoder.encode(data);
            data = bytes;
        }
        
        // Convert bytes to base64
        let binary = '';
        const bytes = new Uint8Array(data);
        const len = bytes.byteLength;
        
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        
        return btoa(binary);
    } catch (error) {
        console.error('Base64 encoding error:', error);
        return '';
    }
}

// Safe base64 decoding that handles errors
function safeBase64Decode(str) {
    try {
        // Clean up the string first
        str = cleanBase64String(str);
        
        if (!str) return new Uint8Array(0);
        
        // Decode
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        
        return bytes;
    } catch (error) {
        console.error('Base64 decoding error:', error);
        return new Uint8Array(0);
    }
}

// Check if a string is valid base64
function isValidBase64(str) {
    if (!str) return false;
    
    // Quick regex test
    if (!/^[A-Za-z0-9+/=]+$/.test(str)) return false;
    
    try {
        // Try decoding
        atob(cleanBase64String(str));
        return true;
    } catch (e) {
        return false;
    }
}

// Module exports for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        cleanBase64String,
        safeBase64Encode,
        safeBase64Decode,
        isValidBase64
    };
}
