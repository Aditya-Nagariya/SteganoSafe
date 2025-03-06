"""
Utility functions for handling base64 encoding/decoding with enhanced error recovery
"""
import base64
import logging
import re

logger = logging.getLogger(__name__)

def safe_base64_encode(data):
    """
    Safely encode data to base64, handling potential encoding errors
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        encoded = base64.b64encode(data)
        return encoded.decode('ascii')
    except Exception as e:
        logger.error(f"Base64 encoding error: {str(e)}")
        raise ValueError(f"Failed to encode data to base64: {str(e)}")

def safe_base64_decode(encoded_data):
    """
    Safely decode base64 data with error handling and recovery mechanisms
    """
    try:
        # First try direct decoding
        if isinstance(encoded_data, bytes):
            encoded_data = encoded_data.decode('ascii', errors='replace')
        
        # Fix common base64 encoding issues
        cleaned_data = encoded_data.strip()
        
        # Fix padding if needed
        padding_needed = len(cleaned_data) % 4
        if padding_needed:
            cleaned_data += '=' * (4 - padding_needed)
            
        # Replace invalid chars with valid base64 chars
        cleaned_data = re.sub(r'[^A-Za-z0-9+/=]', 'A', cleaned_data)
        
        return base64.b64decode(cleaned_data)
    
    except Exception as e:
        logger.warning(f"Standard base64 decoding failed: {str(e)}. Trying recovery mode.")
        
        try:
            # Try more aggressive cleaning
            # Keep only valid base64 characters
            only_valid = ''.join(c for c in encoded_data if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            
            # Fix padding
            while len(only_valid) % 4 != 0:
                only_valid += '='
                
            # Try decoding again
            return base64.b64decode(only_valid)
        
        except Exception as e2:
            logger.error(f"Base64 recovery decoding also failed: {str(e2)}")
            # Return empty bytes as last resort
            return b''

def is_valid_base64(s):
    """Check if a string is valid base64"""
    try:
        # Check if padding is correct
        padding_correct = len(s) % 4 == 0
        
        # Check if string only contains valid base64 characters
        valid_chars = re.match(r'^[A-Za-z0-9+/=]+$', s) is not None
        
        # Quick check to see if decoding works
        if padding_correct and valid_chars:
            base64.b64decode(s)
            return True
        return False
    except Exception:
        return False

def fix_base64_padding(s):
    """Add padding to a base64 string if needed"""
    if len(s) % 4 == 0:
        return s
    return s + '=' * (4 - len(s) % 4)
