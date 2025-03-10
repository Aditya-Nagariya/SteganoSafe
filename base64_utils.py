"""
Utility functions for handling base64 data with improved error handling
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

def safe_base64_decode(data):
    """
    Safely decode base64 data with error handling for corrupted data
    """
    if not data:
        return None
        
    # If data is bytes, convert to string
    if isinstance(data, bytes):
        try:
            data = data.decode('ascii', errors='replace')
        except Exception as e:
            logger.error(f"Error decoding bytes to ascii: {e}")
            
    # Make sure we're working with a string
    if not isinstance(data, str):
        data = str(data)
            
    # Clean up the base64 string to handle common errors
    
    # 1. Keep only valid base64 characters
    clean_data = re.sub(r'[^A-Za-z0-9+/=]', '', data)
    
    # 2. Fix padding
    remainder = len(clean_data) % 4
    if remainder > 0:
        clean_data += '=' * (4 - remainder)
    
    # 3. Try to decode
    try:
        return base64.b64decode(clean_data)
    except Exception as e:
        logger.error(f"Error decoding base64: {e}")
        
        # 4. Try more aggressive cleaning - only alphanumeric
        alphanumeric_only = re.sub(r'[^A-Za-z0-9]', '', data)
        
        # Add padding if needed
        remainder = len(alphanumeric_only) % 4
        if remainder > 0:
            alphanumeric_only += '=' * (4 - remainder)
            
        try:
            return base64.b64decode(alphanumeric_only + "===")
        except Exception as e2:
            logger.error(f"Second attempt at decoding base64 failed: {e2}")
            
            # 5. Last resort - try various substrings
            for start in range(0, min(20, len(data))):
                try:
                    # Try different starting points
                    substr = data[start:] + "=="
                    return base64.b64decode(substr)
                except:
                    continue
            
            # Nothing worked
            return None

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
