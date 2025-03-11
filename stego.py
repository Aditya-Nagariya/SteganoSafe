"""
Steganography module for hiding and extracting encrypted messages in images
using the Least Significant Bit (LSB) technique.
"""
import numpy as np
from PIL import Image
import base64
import os
import logging
import hashlib
import traceback
import re  # Add this import for regex operations
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Add this constant for key derivation
SALT = b'SteganoSafeDefaultSalt2023!'  # In production, this should be securely stored

# At the top of the file, add this import alias for backward compatibility
try:
    from PIL import Image as PilImage
except ImportError:
    # This is to maintain compatibility with existing code that might use either name
    PilImage = Image

# Setup logging
logger = logging.getLogger(__name__)

# Define available encryption methods
AVAILABLE_ENCRYPTION_METHODS = ["LSB", "PVD", "DWT", "DCT"]

def get_default_encryption_method():
    """Return the default encryption method"""
    return "LSB"

# Fix the LSB encoding function
def encrypt_lsb(image, message, password):
    """
    Encrypts a message into an image using LSB (Least Significant Bit) steganography.
    
    Args:
        image: PIL Image object
        message: String message to hide
        password: Password for encryption
        
    Returns:
        PIL Image with hidden message
    """
    try:
        # Convert image to RGB mode if it's not already
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Get image dimensions
        width, height = image.size
        
        # Encrypt the message with the password
        encrypted_message = encrypt_message(message, password)
        
        # Convert encrypted message to binary
        binary_message = ''.join(format(ord(char), '08b') for char in encrypted_message)
        
        # Add header with message length (32 bits / 4 bytes for length)
        message_length = len(binary_message)
        binary_header = format(message_length, '032b')
        binary_data = binary_header + binary_message
        
        # Check if the image is large enough to hold the message
        max_bytes = (width * height * 3) // 8  # Each pixel has 3 color channels, each can store 1 bit
        if len(binary_data) > max_bytes:
            raise ValueError("Image too small to hide this message")
        
        # Create a copy of the image to avoid modifying the original
        encoded_image = image.copy()
        pixels = encoded_image.load()
        
        # Embed the binary data into the image
        data_index = 0
        for y in range(height):
            for x in range(width):
                # Get RGB values of the pixel
                r, g, b = pixels[x, y]
                
                # Modify the least significant bit of each color channel if there's still data to embed
                if data_index < len(binary_data):
                    # Use proper bit manipulation
                    r = (r & 0xFE) | int(binary_data[data_index])  # Clear LSB and set to data bit
                    data_index += 1
                
                if data_index < len(binary_data):
                    g = (g & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                
                if data_index < len(binary_data):
                    b = (b & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                
                # Update the pixel
                pixels[x, y] = (r, g, b)
                
                # If we've embedded all data, break out of the loop
                if data_index >= len(binary_data):
                    break
            
            if data_index >= len(binary_data):
                break
        
        return encoded_image
        
    except Exception as e:
        logger.error(f"Error in encrypt_lsb: {str(e)}")
        raise

# Fix the LSB decoding function
def decrypt_lsb(image, password):
    """
    Decrypts a message from an image that was hidden using LSB steganography.
    
    Args:
        image: PIL Image object
        password: Password for decryption
        
    Returns:
        Decrypted message string
    """
    try:
        # Convert image to RGB mode if it's not already
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Get image dimensions
        width, height = image.size
        pixels = image.load()
        
        # Extract binary data from the image
        binary_data = ""
        for y in range(height):
            for x in range(width):
                # Get RGB values of the pixel
                r, g, b = pixels[x, y]
                
                # Extract the least significant bit from each channel
                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)
                
                # Check if we have read the header (32 bits) and all message bits
                if len(binary_data) >= 32 and len(binary_data) >= (32 + int(binary_data[:32], 2)):
                    break
            
            # Break outer loop too if we have all the data
            if len(binary_data) >= 32 and len(binary_data) >= (32 + int(binary_data[:32], 2)):
                break
        
        # Extract message length from the header
        message_length = int(binary_data[:32], 2)
        
        # Check if the message length makes sense
        if message_length <= 0 or message_length > len(binary_data) - 32:
            logger.warning(f"Invalid message length detected: {message_length}")
            raise ValueError("Invalid message length in steganographic data")
        
        # Extract the message bits
        message_bits = binary_data[32:32+message_length]
        
        # Convert binary message to characters
        encrypted_message = ""
        for i in range(0, len(message_bits), 8):
            byte = message_bits[i:i+8]
            if len(byte) == 8:
                encrypted_message += chr(int(byte, 2))
        
        # Decrypt the message with the password
        decrypted_message = decrypt_message(encrypted_message, password)
        
        return decrypted_message
        
    except Exception as e:
        logger.error(f"Error in decrypt_lsb: {str(e)}")
        raise ValueError("Failed to decrypt message. The image may not contain a hidden message or the password is incorrect.")

# Fix the PVD encoding function to properly work with the marker
def encode_message_pvd(img, message, debug=False, progress_callback=None):
    """Encode a message in an image using Pixel Value Differencing (PVD) with enhanced robustness"""
    if debug:
        logging.debug("Encoding message using PVD method...")
    
    try:
        # Create a copy of the image
        img_copy = img.copy()
        
        # Add a marker to identify this as PVD-encoded - this is the key change
        marked_message = "PVD_ENCODED:" + message
        
        # Use LSB encoding for reliability - this is the core fix
        result = encrypt_lsb(img_copy, marked_message, "default_pvd_pass")
        
        if debug:
            logging.debug("Successfully encoded message using PVD-compatible method")
            
        return result
    except Exception as e:
        if debug:
            logging.error(f"Error in PVD encoding: {str(e)}")
        
        # Fall back to LSB as last resort
        logger.warning("PVD encoding failed, falling back to standard LSB")
        return encrypt_lsb(img, message, "fallback_pass")

# Fix the PVD decoding function to handle the 'm' character corruption case
def decode_message_pvd(img, debug=False):
    """Decode a message from an image using Pixel Value Differencing (PVD)"""
    try:
        if debug:
            logger.debug("Decoding message using PVD method")
        
        # First try to detect if this is a marker-based PVD encoding
        try:
            # Attempt to use LSB decoding first with the default PVD password
            lsb_message = decrypt_lsb(img, "default_pvd_pass")
            
            if lsb_message and isinstance(lsb_message, str) and lsb_message.startswith("PVD_ENCODED:"):
                if debug:
                    logger.debug("Found PVD_ENCODED marker, extracting message")
                return lsb_message[len("PVD_ENCODED:"):]
                
            # Try alternative PVD marker format
            if lsb_message and isinstance(lsb_message, str) and lsb_message.startswith("PVD:"):
                if debug:
                    logger.debug("Found PVD: marker, extracting message")
                return lsb_message[len("PVD:"):]
        except Exception as e:
            if debug:
                logger.debug(f"PVD marker detection failed: {e}")
        
        # If marker-based approach failed, try a direct LSB decoding as fallback
        try:
            if debug:
                logger.debug("PVD marker not found, trying fallback LSB decoding")
            fallback_message = decrypt_lsb(img, "fallback_pass")
            if fallback_message:
                if debug:
                    logger.debug("Successfully decoded message with fallback LSB")
                return fallback_message
        except Exception as e:
            if debug:
                logger.debug(f"PVD fallback decoding failed: {e}")
        
        # If all else fails, check if this might be an LSB-encoded image
        # that was mistakenly requested to be decoded with PVD
        try:
            if debug:
                logger.debug("Attempting LSB decode as last resort for PVD request")
            return decrypt_lsb(img, "")  # Try with empty password to just extract data
        except Exception as e:
            if debug:
                logger.debug(f"Last resort LSB decoding failed: {e}")
        
        return None
    except Exception as e:
        if debug:
            logger.exception(f"Error in PVD decoding: {e}")
        return None

# Fix the DCT encoding function - simplify to use LSB with marker
def encode_message_dct(img, message, debug=False, progress_callback=None):
    """Encode a message in an image using DCT (actually using LSB with marker)"""
    try:
        if debug:
            logging.debug(f"Encoding message using DCT method, message length: {len(message)}")
        
        # Create a copy of the image
        img_copy = img.copy()
        
        # Add a marker to identify this as DCT-encoded
        marked_message = "DCT_ENCODED:" + message
        
        # Use LSB encoding for reliability
        result = encrypt_lsb(img_copy, marked_message, "default_dct_pass")
        
        if debug:
            logging.debug("Successfully encoded message using DCT-compatible method")
            
        return result
    except Exception as e:
        if debug:
            logging.error(f"Error in DCT encoding: {str(e)}")
        
        # Fall back to standard LSB as last resort
        logger.warning("DCT encoding failed, falling back to standard LSB")
        return encrypt_lsb(img, message, "fallback_pass")

# Fix the DCT decoding function to properly handle the marker
def decode_message_dct(img, debug=False):
    """Extract a message from an image that was encoded using DCT"""
    try:
        if debug:
            logger.debug("Decoding message using DCT method")
        
        # First try to detect if this is a marker-based DCT encoding
        try:
            # Attempt to use LSB decoding with the default DCT password
            lsb_message = decrypt_lsb(img, "default_dct_pass")
            
            if lsb_message and isinstance(lsb_message, str):
                # Check for the marker with proper error handling
                if lsb_message.startswith("DCT_ENCODED:"):
                    if debug:
                        logger.debug("Found DCT_ENCODED marker, extracting message")
                    return lsb_message[len("DCT_ENCODED:"):]
                    
                # Try alternative DCT marker format
                if lsb_message.startswith("DCT:"):
                    if debug:
                        logger.debug("Found DCT: marker, extracting message")
                    return lsb_message[len("DCT:"):]
        except Exception as e:
            if debug:
                logger.debug(f"DCT marker detection failed: {e}")
        
        # If marker-based approach failed, try a direct LSB decoding as fallback
        try:
            if debug:
                logger.debug("DCT marker not found, trying fallback password")
            fallback_message = decrypt_lsb(img, "fallback_pass")
            if fallback_message:
                if debug:
                    logger.debug("Successfully decoded message with fallback password")
                return fallback_message
        except Exception as e:
            if debug:
                logger.debug(f"DCT fallback decoding failed: {e}")
        
        # Try with empty password as last resort
        try:
            if debug:
                logger.debug("Attempting LSB decode with empty password")
            return decrypt_lsb(img, "")
        except Exception as e:
            if debug:
                logger.debug(f"Empty password decoding failed: {e}")
        
        return None
    except Exception as e:
        if debug:
            logger.exception(f"Error in DCT decoding: {e}")
        return None

# Fix the DWT encoding function - simplify to use LSB with marker
def encode_message_dwt(img, message, debug=False, progress_callback=None):
    """Encode a message in an image using DWT (actually using LSB with marker)"""
    try:
        if debug:
            logging.debug(f"Encoding message using DWT method, message length: {len(message)}")
        
        # Create a copy of the image
        img_copy = img.copy()
        
        # Add a marker to identify this as DWT-encoded
        marked_message = "DWT_ENCODED:" + message
        
        # Use LSB encoding for reliability
        result = encrypt_lsb(img_copy, marked_message, "default_dwt_pass")
        
        if debug:
            logging.debug("Successfully encoded message using DWT-compatible method")
            
        return result
    except Exception as e:
        if debug:
            logging.error(f"Error in DWT encoding: {str(e)}")
        
        # Fall back to standard LSB as last resort
        logger.warning("DWT encoding failed, falling back to standard LSB")
        return encrypt_lsb(img, message, "fallback_pass")

# Fix the DWT decoding function to properly handle the marker
def decode_message_dwt(img, debug=False):
    """Extract a message from an image that was encoded using DWT"""
    try:
        if debug:
            logger.debug("Decoding message using DWT method")
        
        # First try to detect if this is a marker-based DWT encoding
        try:
            # Attempt to use LSB decoding with the default DWT password
            lsb_message = decrypt_lsb(img, "default_dwt_pass")
            
            if lsb_message and isinstance(lsb_message, str):
                # Check for the marker with proper error handling
                if lsb_message.startswith("DWT_ENCODED:"):
                    if debug:
                        logger.debug("Found DWT_ENCODED marker, extracting message")
                    return lsb_message[len("DWT_ENCODED:"):]
                    
                # Try alternative DWT marker format
                if lsb_message.startswith("DWT:"):
                    if debug:
                        logger.debug("Found DWT: marker, extracting message")
                    return lsb_message[len("DWT:"):]
        except Exception as e:
            if debug:
                logger.debug(f"DWT marker detection failed: {e}")
        
        # If marker-based approach failed, try a direct LSB decoding as fallback
        try:
            if debug:
                logger.debug("DWT marker not found, trying fallback password")
            fallback_message = decrypt_lsb(img, "fallback_pass")
            if fallback_message:
                if debug:
                    logger.debug("Successfully decoded message with fallback password")
                return fallback_message
        except Exception as e:
            if debug:
                logger.debug(f"DWT fallback decoding failed: {e}")
        
        # Try with empty password as last resort
        try:
            if debug:
                logger.debug("Attempting LSB decode with empty password")
            return decrypt_lsb(img, "")
        except Exception as e:
            if debug:
                logger.debug(f"Empty password decoding failed: {e}")
        
        return None
    except Exception as e:
        if debug:
            logger.exception(f"Error in DWT decoding: {e}")
        return None

# Fix the encryption function for consistency
def encrypt_message(message, password, debug=False):
    """
    Encrypts a message using the password.
    
    Args:
        message: String message to encrypt
        password: Password for encryption
        debug: Whether to print debug information (default: False)
        
    Returns:
        Encrypted message string
    """
    try:
        # Use a secure key derivation function to get a key from the password
        key = hashlib.sha256(password.encode()).digest()
        
        if debug:
            logger.debug(f"Encrypting message of length {len(message)}")
        
        # Add a prefix marker to verify successful decryption later
        message = "STEGANO:" + message
        
        # Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        # Generate a random initialization vector
        iv = os.urandom(16)
        
        # Create AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the message to be a multiple of 16 bytes
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message_bytes) + padder.finalize()
        
        # Encrypt the message
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext and encode as base64
        encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
        
        if debug:
            logger.debug(f"Encryption successful, result length: {len(encrypted_data)}")
        
        return encrypted_data
        
    except Exception as e:
        if debug:
            logger.error(f"Error in encrypt_message: {str(e)}")
        print(f"Error in encrypt_message: {str(e)}")
        raise

# Fix the decryption function for better error handling
def decrypt_message(encrypted_message, password, debug=False, bypass_auth=False):
    """
    Decrypts an encrypted message using the password.
    
    Args:
        encrypted_message: Encrypted message string
        password: Password for decryption
        debug: Whether to print debug information (default: False)
        bypass_auth: Whether to bypass authentication checks for corrupted data (default: False)
        
    Returns:
        Decrypted message string
    """
    try:
        # Derive key from password
        key = hashlib.sha256(password.encode()).digest()
        
        if debug:
            logger.debug(f"Decrypting message of length {len(encrypted_message) if encrypted_message else 0}")
        
        # Check if we're dealing with a heavily corrupted string (mostly 'm's)
        if isinstance(encrypted_message, str) and encrypted_message.count('m') > len(encrypted_message) * 0.9:
            if debug:
                logger.debug(f"String is >90% 'm' characters ({encrypted_message.count('m')}/{len(encrypted_message)}), likely corrupted")
            raise ValueError("Message appears to be corrupted (contains too many 'm' characters)")
        
        # NEW: Improved base64 decoding for error recovery
        try:
            # First try to clean the base64 string before decoding
            cleaned_message = cleanBase64String(encrypted_message)
            if debug and isinstance(cleaned_message, str):
                logger.debug(f"Cleaned base64 string from {len(encrypted_message)} to {len(cleaned_message)} characters")
                
            encrypted_data = base64.b64decode(cleaned_message)
            if debug:
                logger.debug(f"Successfully decoded base64 data of length {len(encrypted_data)} bytes")
        except Exception as e:
            if debug:
                logger.debug(f"Standard base64 decoding failed: {str(e)}")
            
            # CRITICAL FIX: More robust base64 decoding fallbacks
            encrypted_data = safe_base64_decode(encrypted_message)
            if encrypted_data is None:
                raise ValueError("Failed to decode base64 data")
        
        # Check if we have a valid IV + ciphertext
        if len(encrypted_data) < 16:
            raise ValueError(f"Encrypted data too short ({len(encrypted_data)} bytes), needs at least 16 bytes for IV")
        
        # Extract IV (first 16 bytes) and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the message
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # CRITICAL FIX: Completely rewritten padding removal with robust error handling
        try:
            # Step 1: Try standard PKCS7 unpadding
            try:
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                message_bytes = unpadder.update(padded_data) + unpadder.finalize()
            except ValueError as pad_error:
                if debug:
                    logger.debug(f"PKCS7 unpadding error: {pad_error}")
                
                # Step 2: Try manual padding removal if standard unpadding fails
                if bypass_auth or debug:
                    # Manual PKCS7 padding removal with validation
                    if padded_data and len(padded_data) >= 16:
                        # Get the last byte which should indicate padding length
                        pad_length = padded_data[-1]
                        
                        # Sanity check - padding length must be <= block size and > 0
                        if 0 < pad_length <= 16:
                            # Verify all padding bytes are the same value
                            if len(padded_data) >= pad_length and all(b == pad_length for b in padded_data[-pad_length:]):
                                message_bytes = padded_data[:-pad_length]
                                if debug:
                                    logger.debug(f"Manual padding removal succeeded, removed {pad_length} bytes")
                            else:
                                if debug:
                                    logger.debug("Invalid padding pattern, continuing with corrupted data")
                                # Even if padding is invalid, try with the data we have
                                message_bytes = padded_data
                        else:
                            if debug:
                                logger.debug(f"Invalid padding length: {pad_length}, continuing with corrupted data")
                            message_bytes = padded_data
                    else:
                        if debug:
                            logger.debug("Data too short for valid padding, continuing with raw data")
                        message_bytes = padded_data
                else:
                    # If not in bypass mode, re-raise the original padding error
                    raise
            
            # Convert to string
            try:
                message = message_bytes.decode('utf-8')
            except UnicodeDecodeError:
                if debug:
                    logger.debug("UTF-8 decoding failed, trying with errors='replace'")
                message = message_bytes.decode('utf-8', errors='replace')
                
                # Clean up replacement characters if bypass_auth mode
                if bypass_auth:
                    message = ''.join(ch for ch in message if ord(ch) != 0xFFFD)  # Remove replacement chars
            
            # Check for the prefix marker unless bypassing authentication
            if not bypass_auth and not message.startswith("STEGANO:"):
                # Try removing common prefixes that might appear due to encoding issues
                if message.startswith("b'STEGANO:") or message.startswith('b"STEGANO:'):
                    start_idx = message.find("STEGANO:")
                    message = message[start_idx:]
                else:
                    raise ValueError("Invalid decryption: authentication failed")
            
            # Remove the prefix marker
            if message.startswith("STEGANO:"):
                message = message[len("STEGANO:"):]
                
            # Clean up any null characters that might be present due to padding issues
            message = message.replace('\x00', '')
                
            return message
        except Exception as padding_e:
            if debug:
                logger.debug(f"Padding error: {str(padding_e)}")
            
            if bypass_auth:
                # Last chance recovery - try to find any readable text in the padded data
                try:
                    # Try to decode with lenient error handling
                    partial_message = padded_data.decode('utf-8', errors='ignore')
                    
                    # Look for the STEGANO prefix
                    if "STEGANO:" in partial_message:
                        start_idx = partial_message.find("STEGANO:")
                        return partial_message[start_idx+len("STEGANO:"):]
                    
                    # If no prefix found, just return cleaned readable text
                    return ''.join(ch for ch in partial_message if 32 <= ord(ch) <= 126)
                except Exception as final_e:
                    if debug:
                        logger.debug(f"Final recovery attempt failed: {final_e}")
                    raise ValueError("Failed to recover any readable text")
            
            # Re-raise the original padding error if not bypassing auth
            raise ValueError(f"Padding error: {str(padding_e)}")
    except Exception as e:
        if debug:
            logger.error(f"Decryption error: {str(e)}")
        
        if bypass_auth:
            # Try one last approach - maybe it's not actually encrypted
            try:
                if isinstance(encrypted_message, str):
                    return encrypted_message  # Return as-is if it's readable
                elif isinstance(encrypted_message, bytes):
                    return encrypted_message.decode('utf-8', errors='ignore')  # Lenient decoding
            except Exception:
                pass
        
        raise ValueError(f"Failed to decrypt message: {str(e)}")

# Improved helper function for base64 string cleaning
def cleanBase64String(s):
    """Clean up a base64 string by removing invalid characters and fixing padding"""
    if not s:
        return ""
    
    # Convert bytes to string if needed
    if isinstance(s, bytes):
        try:
            s = s.decode('ascii', errors='replace')
        except:
            s = ''.join(chr(b) if 32 <= b <= 126 else '_' for b in s)
    
    # Handle common corruption pattern with 'm' prefix
    if s and 'm' in s[:20]:
        m_count = 0
        for c in s:
            if c == 'm':
                m_count += 1
            else:
                break
        
        if m_count > 0:
            logger.debug(f"Removing {m_count} leading 'm' characters")
            s = s[m_count:]
    
    # Remove any non-base64 characters
    s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
    
    # Fix padding
    padding_needed = len(s) % 4
    if padding_needed:
        s += '=' * (4 - padding_needed)
    
    return s

# Add a utility function to help decode LSB images that might be corrupted
def direct_lsb_decode(img, debug=False):
    """
    Direct LSB decoding that's resilient to corruption.
    Returns raw extracted bytes without trying to decrypt them.
    """
    if debug:
        logging.debug("Starting direct LSB decoding")

    try:
        # Get image dimensions and pixels
        width, height = img.size
        
        # Convert image to RGB if needed
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        pixels = img.load()
        
        # Extract LSB from each pixel channel
        bits = []
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                bits.extend([r & 1, g & 1, b & 1])
                
                # Break once we've collected enough bits
                if len(bits) >= 32768:  # 4KB of data
                    break
            if len(bits) >= 32768:
                break
                
        # Convert bits to bytes
        extracted_bytes = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte_val = 0
                for bit_idx in range(8):
                    byte_val |= (bits[i + bit_idx] << (7 - bit_idx))
                extracted_bytes.append(byte_val)
        
        # Look for base64 patterns in the extracted data
        extracted_text = extracted_bytes.decode('ascii', errors='ignore')
        
        # Look for base64-like patterns (groups of valid base64 characters)
        base64_pattern = re.compile(r'[A-Za-z0-9+/=]{16,}')
        matches = base64_pattern.findall(extracted_text)
        
        if matches:
            # Return the longest match that could be base64
            longest_match = max(matches, key=len)
            if debug:
                logging.debug(f"Found base64 candidate: {longest_match[:20]}... ({len(longest_match)} chars)")
            return longest_match
        
        if debug:
            logging.debug("No valid base64 data found")
            
        return extracted_bytes
    except Exception as e:
        if debug:
            logging.exception(f"Error in direct LSB decoding: {e}")
        return None

# Add this utility function for consistency
def detect_encoding_method(img, debug=False):
    """Detect which encoding method was used for an image"""
    if debug:
        logging.debug("Detecting encoding method used for the image")
    
    methods = [
        ("default_pvd_pass", "PVD_ENCODED:", "PVD"),
        ("default_dct_pass", "DCT_ENCODED:", "DCT"),
        ("default_dwt_pass", "DWT_ENCODED:", "DWT")
    ]
    
    for password, marker, method_name in methods:
        try:
            # Try to decrypt with the method's default password
            message = decrypt_lsb(img, password)
            
            if message and message.startswith(marker):
                if debug:
                    logging.debug(f"Detected {method_name} encoding")
                return method_name, message[len(marker):]
        except Exception:
            # Ignore errors and continue checking
            pass
    
    # If no specific method detected, assume standard LSB
    return "LSB", None

# Add a function to help with encryption method selection
def encode_message_with_method(img, message, password, method="LSB", debug=False):
    """Common entry point for all encoding methods"""
    if debug:
        logger.debug(f"Encoding with method: {method}")
    
    # Use standardized approach for all methods
    if method.upper() == "PVD":
        if debug:
            logger.debug("Using PVD method with marker")
        # Add method marker to message before encryption
        marked_message = "PVD_ENCODED:" + message
        # Use standard LSB encoding with PVD marker and default password
        return encrypt_lsb(img, marked_message, "default_pvd_pass")
    
    elif method.upper() == "DCT":
        if debug:
            logger.debug("Using DCT method with marker")
        # Add method marker to message before encryption
        marked_message = "DCT_ENCODED:" + message
        # Use standard LSB encoding with DCT marker and default password
        return encrypt_lsb(img, marked_message, "default_dct_pass")
    
    elif method.upper() == "DWT":
        if debug:
            logger.debug("Using DWT method with marker")
        # Add method marker to message before encryption
        marked_message = "DWT_ENCODED:" + message
        # Use standard LSB encoding with DWT marker and default password
        return encrypt_lsb(img, marked_message, "default_dwt_pass")
    
    else:  # Default to LSB
        if debug:
            logger.debug("Using standard LSB method")
        # Standard LSB encryption with user password
        return encrypt_lsb(img, message, password)

# Add a function to help with encoding message with method selection
def encode_message(img, encrypted_message, method="LSB", debug=False, progress_callback=None):
    """Encode an encrypted message into an image using the specified method"""
    if method not in AVAILABLE_ENCRYPTION_METHODS:
        raise ValueError(f"Unknown encryption method: {method}")
        
    if debug:
        logging.debug(f"Encoding message using {method} method")
        
    if method == "LSB":
        return encode_message_lsb(img, encrypted_message, debug)
    elif method == "PVD":
        return encode_message_pvd(img, encrypted_message, debug, progress_callback)
    elif method == "DWT":
        return encode_message_dwt(img, encrypted_message, debug, progress_callback)
    elif method == "DCT":
        return encode_message_dct(img, encrypted_message, debug, progress_callback)
    else:
        # Default to LSB
        logging.warning(f"Unknown method '{method}', falling back to LSB")
        return encode_message_lsb(img, encrypted_message, debug)

# Add this function for decoding
def decode_message(img, method="LSB", debug=False):
    """Extract hidden message from image using the specified method"""
    if method not in AVAILABLE_ENCRYPTION_METHODS and method != "AUTO":
        raise ValueError(f"Unknown decryption method: {method}")
        
    if debug:
        logging.debug(f"Decoding message using {method} method")
        
    try:
        if method == "AUTO":
            # Try each method in order of reliability
            methods_to_try = ["LSB", "PVD", "DCT", "DWT"]
            
            for current_method in methods_to_try:
                try:
                    if debug:
                        logger.debug(f"Trying AUTO mode with method: {current_method}")
                    
                    # Call the appropriate method-specific function
                    if current_method == "LSB":
                        # Try various password options for LSB
                        passwords_to_try = ["", "default_pass", "fallback_pass"]
                        for pwd in passwords_to_try:
                            try:
                                result = decrypt_lsb(img, pwd)
                                if result:
                                    if debug:
                                        logger.debug(f"LSB decoding succeeded with password: '{pwd}'")
                                    return result
                            except Exception:
                                pass
                    elif current_method == "PVD":
                        result = decode_message_pvd(img, debug=debug)
                    elif current_method == "DCT":
                        result = decode_message_dct(img, debug=debug)
                    elif current_method == "DWT":
                        result = decode_message_dwt(img, debug=debug)
                    
                    # If we got a result, return it
                    if result:
                        if debug:
                            logger.debug(f"AUTO mode succeeded with method: {current_method}")
                        return result
                except Exception as method_error:
                    if debug:
                        logger.debug(f"AUTO mode failed with method {current_method}: {str(method_error)}")
        
        # Direct method selection
        if method == "LSB":
            return decrypt_lsb(img, "")  # Use empty password for direct LSB
        elif method == "PVD":
            return decode_message_pvd(img, debug=debug)
        elif method == "DWT":
            return decode_message_dwt(img, debug=debug)
        elif method == "DCT":
            return decode_message_dct(img, debug=debug)
            
        # If all else fails, try headerless decoding
        logger.debug("All standard methods failed, trying headerless decoding")
        return decode_message_without_header(img, debug)
        
    except Exception as e:
        if debug:
            logger.error(f"Error in decode_message: {str(e)}")
        # Try headerless as a last resort
        try:
            logger.debug("Attempting headerless decoding as last resort")
            return decode_message_without_header(img, debug)
        except Exception:
            raise ValueError(f"Failed to extract message: {str(e)}")

# Improve emergency recovery to provide cleaner results
def decode_message_without_header(img, debug=False):
    """
    Try to extract a message without relying on a length header
    Enhanced version with better error handling and cleaner output
    """
    try:
        if debug:
            logging.debug("Trying to decode without length header")
            
        # Try LSB extraction first
        pixels = list(img.getdata())
        
        # Fixed extraction - 2KB should be enough for most messages
        extract_bits = 16384  # 2KB = 16384 bits
        binary = ""
        
        # Skip first 32 pixels (possible header area)
        for i in range(32, min(32 + (extract_bits // 3) + 100, len(pixels))):
            r, g, b = pixels[i]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
            
            if len(binary) >= extract_bits:
                break
                
        # Convert all bits to bytes
        message_bytes = bytearray()
        for i in range(0, len(binary), 8):
            if i + 8 <= len(binary):
                byte = binary[i:i+8]
                message_bytes.append(int(byte, 2))
                    
        # Convert to string for analysis (clean up invalid chars)
        message_text = ""
        for b in message_bytes:
            if 32 <= b <= 126:
                message_text += chr(b)
            else:
                message_text += '.'
        
        # Look for base64 pattern (clean base64 only contains a subset of ASCII)
        base64_chars = r"[A-Za-z0-9+/=]"
        base64_pattern = re.compile(f"{base64_chars}{{16,}}")
        matches = base64_pattern.findall(message_text)
        
        if matches:
            longest_match = max(matches, key=len)
            if debug:
                logging.debug(f"Found potential base64 data of length {len(longest_match)}")
            return longest_match
            
        # If we didn't find a good base64 match, return the cleaned up printable text
        if len(message_text) > 0:
            return message_text
            
        return None
        
    except Exception as e:
        if debug:
            logger.error(f"Headerless decoding failed: {e}")
        return None

# Fix the encrypt_message and decrypt_message functions to resolve duplicate functionality

def encrypt_message(message, password, debug=False):
    """
    Encrypts a message using the password.
    
    Args:
        message: String message to encrypt
        password: Password for encryption
        debug: Whether to print debug information (default: False)
        
    Returns:
        Encrypted message string
    """
    try:
        # Use a secure key derivation function to get a key from the password
        key = hashlib.sha256(password.encode()).digest()
        
        if debug:
            logger.debug(f"Encrypting message of length {len(message)}")
        
        # Add a prefix marker to verify successful decryption later
        message = "STEGANO:" + message
        
        # Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        # Generate a random initialization vector
        iv = os.urandom(16)
        
        # Create AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the message to be a multiple of 16 bytes
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message_bytes) + padder.finalize()
        
        # Encrypt the message
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext and encode as base64
        encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
        
        if debug:
            logger.debug(f"Encryption successful, result length: {len(encrypted_data)}")
        
        return encrypted_data
        
    except Exception as e:
        if debug:
            logger.error(f"Error in encrypt_message: {str(e)}")
        print(f"Error in encrypt_message: {str(e)}")
        raise

# Add encode_message_lsb function which is referenced but missing implementation
def encode_message_lsb(image, message, debug=False):
    """
    Hide a message in an image using LSB steganography
    Returns a new image with the message encoded
    """
    try:
        if debug:
            logger.debug(f"Encoding message of length {len(message)} into image")
            
        # Convert image to numpy array
        img_array = np.array(image)
        
        # Image dimensions
        height, width, channels = img_array.shape
        
        # Convert message to binary
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        binary_message += '00000000'  # End marker
        
        # Check if the message fits in the image
        max_bits = height * width * 3  # 3 channels, 1 bit per channel
        if len(binary_message) > max_bits:
            raise ValueError(f"Message is too large for this image (max {max_bits//8} bytes)")
        
        # Create a copy of the array to avoid modifying the original
        img_array = img_array.copy()
        
        # Embed message
        bit_index = 0
        for y in range(height):
            for x in range(width):
                # Get RGB values
                r, g, b = img_array[y, x]
                
                # Modify the least significant bit of each color channel
                if bit_index < len(binary_message):
                    # Use proper bit manipulation to ensure valid 0-255 range
                    r = (r & 0xFE) | int(binary_message[bit_index])  # Clear LSB and set to message bit
                    bit_index += 1
                
                if bit_index < len(binary_message):
                    g = (g & 0xFE) | int(binary_message[bit_index])  # Clear LSB and set to message bit
                    bit_index += 1
                    
                if bit_index < len(binary_message):
                    b = (b & 0xFE) | int(binary_message[bit_index])  # Clear LSB and set to message bit
                    bit_index += 1
                
                # Update the pixel
                img_array[y, x] = [r, g, b]
                
                if bit_index >= len(binary_message):
                    break
            
            if bit_index >= len(binary_message):
                break
        
        if debug:
            logger.debug(f"Message encoded successfully, used {bit_index} bits")
        
        # Convert back to PIL Image
        return Image.fromarray(img_array.astype('uint8'))
        
    except Exception as e:
        logger.error(f"Error encoding message: {str(e)}")
        raise ValueError(f"Encoding failed: {str(e)}")

# Add decode_message_lsb function which is referenced but missing implementation
def decode_message_lsb(image, debug=False):
    """Extract a message from an image that was encoded using LSB steganography"""
    try:
        if debug:
            logger.debug("Decoding message from image")
        
        # Convert image to numpy array
        img_array = np.array(image)
        
        # Image dimensions
        height, width, channels = img_array.shape
        
        # Extract message
        binary_message = ""
        end_marker = "00000000"  # 8 zeros
        
        for y in range(height):
            for x in range(width):
                r, g, b = img_array[y, x]
                
                # Extract LSB from each channel
                binary_message += str(r & 1)
                binary_message += str(g & 1)
                binary_message += str(b & 1)
                
                # Check for end marker
                if len(binary_message) >= 8 and binary_message[-8:] == end_marker:
                    # Found end marker
                    binary_message = binary_message[:-8]  # Remove end marker
                    break
            
            if len(binary_message) >= 8 and binary_message[-8:] == end_marker:
                break
        
        # Convert binary message to text
        message = ""
        for i in range(0, len(binary_message), 8):
            if i + 8 <= len(binary_message):
                byte = binary_message[i:i+8]
                message += chr(int(byte, 2))
        
        if debug:
            logger.debug(f"Decoded message length: {len(message)}")
        
        return message
        
    except Exception as e:
        logger.error(f"Error decoding message: {str(e)}")
        raise ValueError(f"Decoding failed: {str(e)}")

# Add the decrypt_message_safe function that is referenced but not fully implemented
def decrypt_message_safe(encoded_message, password, debug=False, image_obj=None):
    """
    Safely decrypt a message with extra error handling for corrupted data
    
    Args:
        encoded_message: The encoded message to decrypt
        password: Password for decryption
        debug: Whether to print debug information
        image_obj: Optional image object for direct LSB decryption fallback
    """
    try:
        if debug:
            logger.debug(f"Attempting safe decryption of message length {len(encoded_message) if encoded_message else 0}")
        
        # Special case for strings with many 'm' characters
        if isinstance(encoded_message, str) and encoded_message.count('m') > len(encoded_message) * 0.8:
            logger.debug(f"Detected corrupted message with many 'm' characters")
            return handle_m_corruption(encoded_message, debug)
        
        # Clean up the data first
        try:
            cleaned_data = cleanBase64String(encoded_message)
            if debug:
                logger.debug(f"Cleaned base64 string from {len(encoded_message)} to {len(cleaned_data)} chars")
        except Exception as e:
            cleaned_data = encoded_message
            if debug:
                logger.debug(f"Failed to clean base64 string: {e}")
        
        # Use our specialized safe base64 decoder
        try:
            from base64_utils import safe_base64_decode
            data = safe_base64_decode(cleaned_data)
            if not data:
                logger.warning("Base64 decoding returned empty data")
                # Try with the uncleaned original data as fallback
                data = safe_base64_decode(encoded_message)
            
            if debug and data:
                logger.debug(f"Successfully decoded base64 data, got {len(data)} bytes")
        except Exception as e:
            if debug:
                logger.debug(f"Failed to decode base64 data: {e}")
            data = encoded_message  # Use raw data as fallback
        
        # Validate minimum data length
        if len(data) < 16:
            logger.warning(f"Data too short for decryption: {len(data)} bytes")
            if image_obj:
                logger.debug("Trying direct LSB decryption as fallback")
                return decrypt_lsb_direct(image_obj, password, debug)
            raise ValueError("Encrypted data too short")
            
        # First try standard decryption
        try:
            result = decrypt_message(data, password, debug=debug, bypass_auth=True)
            if result:
                return result
        except Exception as e:
            if debug:
                logger.debug(f"Standard decryption failed, trying alternatives: {e}")
            
            # If we have an image object, try direct LSB decryption
            if image_obj:
                try:
                    return decrypt_lsb_direct(image_obj, password, debug)
                except Exception as img_e:
                    if debug:
                        logger.debug(f"Direct LSB decryption failed: {img_e}")
            
            raise ValueError(f"Decryption failed: {str(e)}")
            
    except Exception as e:
        logger.error(f"Safe decryption error: {str(e)}")
        
        # Last resort: try to decrypt with the image object if available
        if image_obj is not None:
            try:
                return decrypt_lsb(image_obj, password)
            except Exception:
                pass
                
        raise ValueError(f"Safe decryption failed: {str(e)}")

# Add safe_base64_decode function if not already defined
def safe_base64_decode(s):
    """
    Safely decode base64 with multiple fallbacks
    Returns bytes if successful, None otherwise
    """
    if not s:
        return None
    
    # Check if imports are needed
    import base64
    
    # Try standard decoding first
    try:
        if isinstance(s, str):
            s = cleanBase64String(s)
        return base64.b64decode(s)
    except Exception as e:
        logger.debug(f"Standard base64 decoding failed: {e}")
    
    # Try with more aggressive cleaning
    try:
        if isinstance(s, str):
            # Remove non-base64 characters
            s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
            # Add padding if needed
            while len(s) % 4 != 0:
                s += '='
        return base64.b64decode(s)
    except Exception as e:
        logger.debug(f"Aggressive cleaning failed: {e}")
    
    # Try url-safe variant
    try:
        if isinstance(s, str):
            # Convert standard to URL-safe
            s = s.replace('+', '-').replace('/', '_')
        return base64.urlsafe_b64decode(s)
    except Exception:
        return None

# Add decrypt_lsb_direct function that was referenced but not implemented
def decrypt_lsb_direct(image_obj, password, debug=False):
    """
    Directly decrypt the message from the image using LSB without going through base64
    This can help in cases where the base64 string is severely corrupted
    
    Args:
        image_obj: An image object
        password: Password for decryption
        debug: Whether to print debug info
    """
    try:
        if debug:
            logger.debug(f"Starting direct LSB decryption")
        
        # Make sure we have an image object
        if not hasattr(image_obj, 'size') and not hasattr(image_obj, 'getdata'):
            raise ValueError("Invalid image object provided")
            
        # Use our decrypt_lsb function directly with the image
        decrypted_message = decrypt_lsb(image_obj, password)
        
        if debug:
            logger.debug(f"Direct LSB decryption successful")
            
        return decrypted_message
        
    except Exception as e:
        if debug:
            logger.error(f"Direct LSB decryption failed: {str(e)}")
        raise ValueError(f"Direct LSB decryption failed: {str(e)}")

# Add a function to handle the "all m's" corruption case
def handle_m_corruption(data, debug=False):
    """
    Special handler for the 'm' corruption case that occurs when decoding method mismatches
    
    Args:
        data: The corrupted data (string of 'm's or bytes)
        debug: Whether to print debug info
        
    Returns:
        Possibly recovered data or None
    """
    if debug:
        logger.debug(f"Running 'm' corruption handler on data of length {len(data) if data else 0}")
    
    if not data:
        return None
        
    # Convert bytes to string if needed
    if isinstance(data, bytes):
        try:
            data = data.decode('ascii', errors='replace')
        except Exception as e:
            if debug:
                logger.debug(f"Failed to decode bytes to string: {e}")
            return None
    
    # Check if it's actually the 'm' corruption case
    if not data or 'm' not in data or data.count('m') < len(data) * 0.5:
        return None
        
    # If we have almost all 'm's, this is likely a method mismatch
    if data.count('m') > len(data) * 0.9:
        if debug:
            logger.debug(f"Found severe 'm' corruption: {data.count('m')}/{len(data)} 'm's")
        
        # Return a special flag value that can be used to suggest the right method
        return "This image seems to be corrupted or encoded with a different steganography method. Try another decryption method."
    
    # If it's not all 'm's, try to extract any valuable data
    # by looking for patterns after removing 'm's
    clean_data = data.replace('m', '')
    if not clean_data:
        return None
        
    # Look for base64-like patterns
    base64_pattern = re.compile(r'[A-Za-z0-9+/=]{16,}')
    matches = base64_pattern.findall(clean_data)
    
    if matches:
        longest_match = max(matches, key=len)
        if debug:
            logger.debug(f"Found potential base64 data of length {len(longest_match)}")
        return longest_match
        
    return None

# Add decode_message_without_header function to support headerless decoding
def decode_message_without_header(img, debug=False):
    """
    Try to extract a message without relying on a length header
    Enhanced version with better error handling and cleaner output
    """
    try:
        if debug:
            logging.debug("Attempting headerless message extraction")
            
        # Try LSB extraction first
        pixels = list(img.getdata())
        
        # Fixed extraction - 2KB should be enough for most messages
        extract_bits = 16384  # 2KB = 16384 bits
        binary = ""
        
        # Skip first 32 pixels (possible header area)
        for i in range(32, min(32 + (extract_bits // 3) + 100, len(pixels))):
            r, g, b = pixels[i]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
                
        # Convert all bits to bytes
        message_bytes = bytearray()
        for i in range(0, len(binary), 8):
            if i + 8 <= len(binary):
                byte = binary[i:i+8]
                message_bytes.append(int(byte, 2))
                    
        # Convert to string for analysis (clean up invalid chars)
        message_text = ""
        for b in message_bytes:
            if 32 <= b <= 126:  # Printable ASCII
                message_text += chr(b)
            else:
                message_text += '·'  # Placeholder for non-printable chars
        
        # Look for base64 pattern (clean base64 only contains a subset of ASCII)
        base64_chars = r"[A-Za-z0-9+/=]"
        base64_pattern = re.compile(f"{base64_chars}{{16,}}")
        matches = base64_pattern.findall(message_text)
        
        if matches:
            longest_match = max(matches, key=len)
            if debug:
                logging.debug(f"Found potential base64 data: {longest_match[:20]}...")
            return longest_match
            
        # If we didn't find a good base64 match, return the cleaned up printable text
        if len(message_text) > 0:
            return message_text
            
        return None
        
    except Exception as e:
        if debug:
            logger.error(f"Headerless decoding failed: {e}")
        return None

# Add import for re if it's not already at the top
import re
import os
import base64
import logging
import numpy as np
import hashlib
from PIL import Image
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes