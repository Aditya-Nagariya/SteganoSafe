"""
Utility functions for handling base64 encoding/decoding
Helps with error recovery in corrupted steganographic data
"""
import base64
import re
import logging

logger = logging.getLogger(__name__)

def clean_base64_string(s):
    """Clean up a base64 string by removing invalid characters and fixing padding"""
    if not s:
        return ""
        
    # Check if input is bytes and convert to string if necessary
    if isinstance(s, bytes):
        try:
            s = s.decode('ascii', errors='replace')
        except:
            # If decoding fails completely, try to make a reasonable string
            s = ''.join(chr(b) if 32 <= b <= 126 else '_' for b in s)
    
    # Handle common corruption pattern with 'm' prefix
    if s and 'm' in s[:20]:
        # Count leading 'm' characters for logging
        m_count = len(s) - len(s.lstrip('m'))
        if m_count > 0:
            logger.debug(f"Found {m_count} leading 'm' characters, removing them")
            s = s.lstrip('m')
            
            # Special case: if after stripping 'm' we only have padding chars or nothing left
            if not s or all(c == '=' for c in s):
                logger.debug("After removing 'm' chars, only padding or nothing left")
                # Try to extract any hidden base64 data in the string
                potential_data = extract_potential_base64(s)
                if potential_data:
                    logger.debug(f"Found potential base64 data: {len(potential_data)} chars")
                    s = potential_data
    
    # Keep only valid base64 characters: A-Z, a-z, 0-9, +, /, =
    original_length = len(s)
    s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
    if len(s) != original_length:
        logger.debug(f"Removed {original_length - len(s)} invalid characters from base64 string")
    
    # Fix padding: ensure string length is multiple of 4
    padding_needed = len(s) % 4
    if padding_needed:
        s += '=' * (4 - padding_needed)
        logger.debug(f"Added {4 - padding_needed} padding characters")
        
    return s

def extract_potential_base64(s):
    """Extract potential base64 data from a corrupted string"""
    # Look for any sequence that might be base64
    potential_matches = re.findall(r'[A-Za-z0-9+/=]{4,}', s)
    if potential_matches:
        # Return the longest match
        return max(potential_matches, key=len)
    return ""

def safe_base64_decode(s):
    """
    Safely decode base64 with multiple fallbacks
    Returns bytes if successful, None otherwise
    """
    if not s:
        return None
    
    # Log original string characteristics for debugging
    if isinstance(s, str):
        logger.debug(f"Input base64 string length: {len(s)}, starts with: {s[:20]}")
    elif isinstance(s, bytes):
        logger.debug(f"Input base64 bytes length: {len(s)}")
    
    # Special case for strings that are almost all 'm' characters
    if isinstance(s, str) and s.count('m') > len(s) * 0.9:
        logger.debug(f"String is >90% 'm' characters ({s.count('m')}/{len(s)}), likely corrupted")
    
    # Clean the string first
    original_length = len(s) if s else 0
    s = clean_base64_string(s)
    
    if not s:
        logger.warning("Base64 string empty after cleaning")
        return None
    
    if original_length != len(s):
        logger.debug(f"String length changed after cleaning: {original_length} → {len(s)}")
    
    # Try standard decoding first
    try:
        result = base64.b64decode(s)
        logger.debug(f"Standard base64 decoding succeeded: {len(result)} bytes")
        return result
    except Exception as e:
        logger.debug(f"Standard base64 decoding failed: {e}")
    
    # Try with more aggressive cleaning approaches
    try:
        # 1. Special handling for strings with many 'm' characters
        if original_length > 0 and isinstance(s, str) and 'm' in s[:20]:
            # Look for the first valid base64 character after the 'm's
            valid_start = re.search(r'[A-Za-z0-9+/]', s)
            if valid_start:
                start_idx = valid_start.start()
                if start_idx > 0:
                    logger.debug(f"Trimming {start_idx} leading characters")
                    s = s[start_idx:]
                    # Reapply padding
                    s = s.rstrip('=')
                    padding_needed = (4 - len(s) % 4) % 4
                    s = s + ('=' * padding_needed)
                    try:
                        result = base64.b64decode(s)
                        logger.debug(f"Decoding succeeded after trimming prefix: {len(result)} bytes")
                        return result
                    except Exception as e:
                        logger.debug(f"Failed after trimming prefix: {e}")
        
        # 2. Remove all padding and re-add
        s_no_padding = s.rstrip('=')
        padding_needed = (4 - len(s_no_padding) % 4) % 4
        s_cleaned = s_no_padding + ('=' * padding_needed)
        try:
            result = base64.b64decode(s_cleaned)
            logger.debug(f"Decoding succeeded after fixing padding: {len(result)} bytes")
            return result
        except Exception as e:
            logger.debug(f"Failed after fixing padding: {e}")
            
        # 3. Try handling URL-safe variants
        try:
            # Convert standard base64 to URL-safe
            s_urlsafe = s.replace('+', '-').replace('/', '_')
            result = base64.urlsafe_b64decode(s_urlsafe)
            logger.debug(f"URL-safe decoding succeeded: {len(result)} bytes")
            return result
        except Exception as e:
            logger.debug(f"URL-safe decoding failed: {e}")
            
            # Try the other direction
            s_standard = s.replace('-', '+').replace('_', '/')
            try:
                result = base64.b64decode(s_standard)
                logger.debug(f"Standard decoding after URL-safe conversion succeeded: {len(result)} bytes")
                return result
            except Exception as e:
                logger.debug(f"Standard decoding after URL-safe conversion failed: {e}")
    except Exception as e:
        logger.debug(f"Error during aggressive cleaning: {e}")
    
    # Try looking for valid base64 substrings
    try:
        # Find the longest valid-looking base64 substring
        chunks = re.findall(r'[A-Za-z0-9+/]{16,}(?:=*)?', s)
        for chunk in sorted(chunks, key=len, reverse=True):
            try:
                padding_needed = (4 - len(chunk) % 4) % 4
                padded = chunk + ('=' * padding_needed)
                result = base64.b64decode(padded)
                if len(result) > 16:  # Only return if it's reasonably sized
                    logger.debug(f"Found valid base64 chunk: {len(chunk)} chars → {len(result)} bytes")
                    return result
            except Exception:
                continue
    except Exception as e:
        logger.debug(f"Error during chunk search: {e}")
    
    # Last resort - try to force decode even broken base64
    try:
        # Clean again with extreme prejudice
        s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
        
        # Ensure length is multiple of 4
        while len(s) % 4 != 0:
            if '=' in s:
                # Remove all padding and add correct padding
                s = s.rstrip('=')
                s += '=' * (4 - (len(s) % 4))
                break
            else:
                # Either truncate or pad
                if len(s) % 4 == 1:
                    s = s[:-1]  # Truncate
                else:
                    s += '=' * (4 - (len(s) % 4))  # Pad
        
        # Replace any remaining problematic characters with valid ones
        s = re.sub(r'[^A-Za-z0-9+/=]', 'A', s)
        
        try:
            result = base64.b64decode(s)
            logger.debug(f"Last resort decoding succeeded: {len(result)} bytes")
            return result
        except Exception as e:
            logger.debug(f"Last resort decoding failed: {e}")
    except Exception as e:
        logger.debug(f"Error during last resort decoding: {e}")
        
    # If we've made it here, all decoding attempts have failed
    logger.warning("All base64 decoding attempts failed")
    return None

def is_valid_base64(s):
    """Check if a string is valid base64"""
    if not s:
        return False
    
    # Basic format check
    if not re.match(r'^[A-Za-z0-9+/=]+$', s):
        return False
    
    # Length check - must be multiple of 4
    if len(s) % 4 != 0:
        return False
    
    # Padding check - = only at end and max 2
    if '=' in s:
        if s[-1] != '=' or s.find('=') < len(s) - 2:
            return False
    
    # Try decoding
    try:
        base64.b64decode(s)
        return True
    except:
        return False
        
def extract_base64_from_text(text):
    """Extract potential base64-encoded strings from a larger text"""
    if not text:
        return []
    
    # Look for base64-like patterns (at least 16 chars of base64 alphabet)
    matches = re.findall(r'[A-Za-z0-9+/]{16,}[=]{0,2}', text)
    
    valid_candidates = []
    for match in matches:
        # Ensure proper padding
        padding_needed = (4 - len(match) % 4) % 4
        padded = match + ('=' * padding_needed)
        
        # Check if it's actually valid base64
        try:
            base64.b64decode(padded)
            valid_candidates.append(padded)
        except:
            pass
    
    return valid_candidates
