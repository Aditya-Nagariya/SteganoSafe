"""
Steganography module for hiding and extracting encrypted messages in images
using the Least Significant Bit (LSB) technique.
"""
import numpy as np
from PIL import Image
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

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

# Add these at the top of stego.py - make sure they're actually defined
AVAILABLE_ENCRYPTION_METHODS = ["LSB", "PVD", "DWT", "DCT"]

def get_default_encryption_method():
    """Return the default encryption method"""
    return "LSB"

def encrypt_message(message, password, debug=False):
    """Encrypt a message using AES-GCM with a password-derived key"""
    try:
        if debug:
            logger.debug(f"Encrypting message of length {len(message)}")
        
        # Generate a random salt
        salt = os.urandom(16)
        
        # Use PBKDF2 to derive a key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Generate a random nonce for AES-GCM
        nonce = os.urandom(12)
        
        # Encrypt the message
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, message.encode(), None)
        
        # Combine salt, nonce, and ciphertext for storage/transmission
        result = salt + nonce + ciphertext
        
        # Encode as base64 for easy handling
        encoded = base64.b64encode(result).decode('utf-8')
        
        if debug:
            logger.debug(f"Encryption successful, result length: {len(encoded)}")
            
        return encoded
        
    except Exception as e:
        logger.error(f"Error encrypting message: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_message(encoded_message, password, debug=False):
    """Decrypt a message that was encrypted with AES-GCM"""
    try:
        if debug:
            logger.debug(f"Decrypting message of length {len(encoded_message)}")
            
        # Decode from base64
        data = base64.b64decode(encoded_message)
        
        # Extract salt, nonce, and ciphertext
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        
        # Derive the same key using the same parameters
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Decrypt the message
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        if debug:
            logger.debug("Decryption successful")
            
        return plaintext.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Error decrypting message: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")

from base64_utils import safe_base64_decode

def decrypt_message_safe(encoded_message, password, debug=False):
    """Safely decrypt a message with extra error handling for corrupted data"""
    try:
        if debug:
            logger.debug(f"Safely decrypting message of length {len(encoded_message)}")
        
        # First try to ensure we're working with ASCII characters
        try:
            # Try to handle potential binary encoding issues
            if isinstance(encoded_message, bytes):
                encoded_message = encoded_message.decode('ascii', errors='replace')
            elif not all(ord(c) < 128 for c in encoded_message):
                encoded_message = ''.join(c if ord(c) < 128 else '_' for c in encoded_message)
                if debug:
                    logger.debug("Replaced non-ASCII characters in base64 string")
        except Exception as e:
            if debug:
                logger.warning(f"Character encoding handling error: {str(e)}")
            
        # Use our specialized safe base64 decoder
        try:
            data = safe_base64_decode(encoded_message)
            if not data:
                raise ValueError("Base64 decoding failed completely")
            
            if debug:
                logger.debug(f"Base64 decoding succeeded, got {len(data)} bytes")
            
        except Exception as e:
            raise ValueError(f"Base64 decoding failed: {str(e)}")
        
        # Validate minimum data length
        if len(data) < 28:  # 16 (salt) + 12 (nonce)
            raise ValueError(f"Decoded data too short: {len(data)} bytes, minimum required: 28")
            
        # Extract salt, nonce, and ciphertext
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        
        # Derive the key using the same parameters
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Decrypt the message
        cipher = AESGCM(key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError(f"AESGCM decryption failed: {str(e)}. Data might be corrupted or wrong password.")
            
        if debug:
            logger.debug("Safe decryption successful")
            
        return plaintext.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Safe decryption error: {str(e)}")
        raise ValueError(f"Safe decryption failed: {str(e)}")

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
        
        # Embed message
        bit_index = 0
        for y in range(height):
            for x in range(width):
                for c in range(channels):
                    if bit_index < len(binary_message):
                        # Replace the least significant bit
                        img_array[y, x, c] = (img_array[y, x, c] & 0xFE) | int(binary_message[bit_index])
                        bit_index += 1
                    else:
                        break
                if bit_index >= len(binary_message):
                    break
            if bit_index >= len(binary_message):
                break
        
        if debug:
            logger.debug(f"Message encoded successfully, used {bit_index} bits")
        
        # Convert back to PIL Image
        return Image.fromarray(img_array)
        
    except Exception as e:
        logger.error(f"Error encoding message: {str(e)}")
        raise ValueError(f"Encoding failed: {str(e)}")

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
        for y in range(height):
            for x in range(width):
                for c in range(channels):
                    # Get the least significant bit
                    binary_message += str(img_array[y, x, c] & 1)
                    
                    # Check if we've reached an end marker (8 zeros)
                    if len(binary_message) >= 8 and binary_message[-8:] == '00000000':
                        # Convert binary to ASCII
                        message = ""
                        for i in range(0, len(binary_message) - 8, 8):
                            byte = binary_message[i:i+8]
                            message += chr(int(byte, 2))
                            
                        if debug:
                            logger.debug(f"Message decoded successfully, length: {len(message)}")
                            
                        return message
        
        # If no end marker is found
        if debug:
            logger.debug("No message found in the image (no end marker detected)")
        
        return None
        
    except Exception as e:
        logger.error(f"Error decoding message: {str(e)}")
        raise ValueError(f"Decoding failed: {str(e)}")

# Fix the PVD encoding function
def encode_message_pvd(img, message, debug=False, progress_callback=None):
    """Encode a message in an image using Pixel Value Differencing (PVD) with enhanced robustness"""
    if debug:
        logging.info("Encoding message using PVD method...")
    
    # Convert image to numpy array and cast to python integers to avoid overflow issues
    img_array = np.array(img).astype(np.int32)  # Use int32 to avoid uint8 overflow
    width, height = img.size
    
    # Convert message to binary
    binary_message = ''.join(format(ord(c), '08b') for c in message)
    binary_message += "00000000"  # Add null terminator
    
    if debug:
        logging.info(f"Message length in bits: {len(binary_message)}")
    
    # Calculate maximum capacity
    max_capacity = estimate_pvd_capacity(img)
    message_size = len(message)
    
    if message_size > max_capacity:
        raise ValueError(f"Message too large for image. Maximum capacity: {max_capacity} bytes, message size: {message_size} bytes")
    
    # Define quantization ranges
    ranges = [
        (0, 7, 3),     # Range 0-7: 3 bits
        (8, 15, 3),    # Range 8-15: 3 bits
        (16, 31, 4),   # Range 16-31: 4 bits
        (32, 63, 5),   # Range 32-63: 5 bits
        (64, 127, 6),  # Range 64-127: 6 bits
        (128, 255, 7)  # Range 128-255: 7 bits
    ]
    
    bit_idx = 0
    total_bits = len(binary_message)
    update_interval = max(1, total_bits // 100)  # Update progress about 100 times
    
    # Create a copy of the array to avoid modifying the original
    modified_array = np.copy(img_array)
    
    # Iterate over pixel pairs
    for i in range(0, height):
        for j in range(0, width - 1, 2):
            if bit_idx >= len(binary_message):
                break
                
            # Get pixel pair - cast to Python ints to avoid NumPy overflow issues
            p1 = int(modified_array[i, j, 0])
            p2 = int(modified_array[i, j + 1, 0])
            
            # Calculate difference (use Python int arithmetic, not NumPy)
            d = abs(p1 - p2)
            
            # Find range
            for lower, upper, bits in ranges:
                if lower <= d <= upper:
                    # Get bits to embed
                    if bit_idx + bits <= len(binary_message):
                        embed_bits = binary_message[bit_idx:bit_idx + bits]
                        bit_idx += bits
                    else:
                        # If we don't have enough bits, pad with zeros
                        embed_bits = binary_message[bit_idx:] + '0' * (bits - (len(binary_message) - bit_idx))
                        bit_idx = len(binary_message)
                    
                    # Convert bits to decimal
                    decimal_value = int(embed_bits, 2)
                    
                    # Calculate new difference - all as Python ints
                    new_d = lower + decimal_value
                    
                    try:
                        # Fixed approach to prevent overflow
                        diff = new_d - d  # How much we need to change the difference by
                        
                        if p1 >= p2:
                            # Calculate adjustments as Python integers
                            half_diff = diff // 2
                            remainder = diff - half_diff  # Use subtraction instead of modulo for remainder
                            
                            # Apply carefully and clamp to valid range
                            new_p1 = max(0, min(255, p1 - half_diff))
                            new_p2 = max(0, min(255, p2 + remainder))
                        else:
                            # Calculate adjustments as Python integers
                            half_diff = diff // 2
                            remainder = diff - half_diff  # Use subtraction instead of modulo for remainder
                            
                            # Apply carefully and clamp to valid range
                            new_p1 = max(0, min(255, p1 + half_diff))
                            new_p2 = max(0, min(255, p2 - remainder))
                        
                        # Update the array with clamped values
                        modified_array[i, j, 0] = new_p1
                        modified_array[i, j + 1, 0] = new_p2
                    except Exception as e:
                        # Just log the error and continue with the next pixel pair
                        logging.error(f"Error processing pixel pair at ({i},{j}): {str(e)}")
                    
                    # Report progress if callback provided
                    if progress_callback and bit_idx % update_interval == 0:
                        progress = (bit_idx / total_bits) * 100
                        progress_callback(progress)
                    
                    break
            
            if bit_idx >= len(binary_message):
                break
        
        if bit_idx >= len(binary_message):
            break
    
    # Make sure we encoded the entire message
    if bit_idx < len(binary_message):
        raise ValueError(f"Unable to encode complete message. Only encoded {bit_idx}/{len(binary_message)} bits.")
    
    # Preserve other channels from original
    modified_array[:, :, 1:] = img_array[:, :, 1:]
    
    # Convert back to uint8 for image creation
    modified_array = np.clip(modified_array, 0, 255).astype(np.uint8)
    
    # Create new image from array
    encoded_img = Image.fromarray(modified_array)
    
    # Final progress update
    if progress_callback:
        progress_callback(100)
    
    return encoded_img

# Fix the PVD decoding function
def decode_message_pvd(img, debug=False):
    """Decode a message from an image using Pixel Value Differencing (PVD) with enhanced error handling"""
    if debug:
        logging.info("Decoding message using PVD method...")
    
    try:
        # Convert image to numpy array - use int32 to avoid uint8 overflow issues
        img_array = np.array(img).astype(np.int32)
        width, height = img.size
        
        # Define the same quantization ranges as used for encoding
        ranges = [
            (0, 7, 3),     # Range 0-7: 3 bits
            (8, 15, 3),    # Range 8-15: 3 bits
            (16, 31, 4),   # Range 16-31: 4 bits
            (32, 63, 5),   # Range 32-63: 5 bits
            (64, 127, 6),  # Range 64-127: 6 bits
            (128, 255, 7)  # Range 128-255: 7 bits
        ]
        
        # Extract bits from the image
        extracted_bits = ""
        null_terminator_count = 0
        
        # Define how many consecutive null bytes indicate end of message
        required_null_terminators = 1
        
        for i in range(height):
            for j in range(0, width - 1, 2):
                if j + 1 >= width:
                    continue  # Skip if we don't have a complete pair
                    
                # Get pixel pair as Python integers
                p1 = int(img_array[i, j, 0])
                p2 = int(img_array[i, j + 1, 0])
                
                # Calculate difference using Python integers to avoid overflow
                d = abs(p1 - p2)
                
                # Find range
                for lower, upper, bits in ranges:
                    if lower <= d <= upper:
                        # Extract decimal value
                        decimal_value = d - lower
                        
                        # Ensure decimal value is within expected range for the number of bits
                        max_value = (1 << bits) - 1  # 2^bits - 1
                        if decimal_value > max_value:
                            decimal_value = max_value
                            
                        # Convert to binary and pad to correct length
                        binary = format(decimal_value, f'0{bits}b')
                        extracted_bits += binary
                        
                        # Check for potential termination sequence
                        if len(extracted_bits) >= 8 and extracted_bits[-8:] == "00000000":
                            null_terminator_count += 1
                            if debug:
                                logging.info(f"Found null terminator ({null_terminator_count}/{required_null_terminators})")
                            if null_terminator_count >= required_null_terminators:
                                # Remove all terminators
                                extracted_bits = extracted_bits[:-8]
                                break
                        break
                
                if null_terminator_count >= required_null_terminators:
                    break
            
            if null_terminator_count >= required_null_terminators:
                break
        
        # If we didn't find a terminator, search for one
        if null_terminator_count < required_null_terminators:
            null_pos = extracted_bits.find("00000000")
            if null_pos >= 0:
                extracted_bits = extracted_bits[:null_pos]
                if debug:
                    logging.info(f"Found null terminator at position {null_pos}")
        
        # Ensure we have complete bytes (pad with zeros if needed)
        padding_needed = (8 - (len(extracted_bits) % 8)) % 8
        if padding_needed > 0:
            extracted_bits += "0" * padding_needed
            if debug:
                logging.info(f"Added {padding_needed} bits of padding for complete bytes")
        
        # Convert binary to text using explicit ASCII encoding for base64 compatibility
        message = ""
        for i in range(0, len(extracted_bits), 8):
            if i + 8 <= len(extracted_bits):
                byte = extracted_bits[i:i+8]
                try:
                    char_code = int(byte, 2)
                    # IMPORTANT: Filter to ASCII-compatible characters only
                    if 32 <= char_code <= 126:  # Printable ASCII range
                        message += chr(char_code)
                    else:
                        # Replace with base64-compatible characters
                        message += 'A'  # Use 'A' as a replacement for non-ASCII chars
                        if debug:
                            logging.warning(f"Non-ASCII character at position {i//8}: {char_code}")
                except ValueError:
                    message += "A"  # Use 'A' as a safe replacement
                    if debug:
                        logging.warning(f"Invalid byte value at position {i}: {byte}")
        
        # Base64 strings should be a multiple of 4 in length
        if message and len(message) % 4 != 0:
            padding = 4 - (len(message) % 4)
            message += '=' * padding
            if debug:
                logging.info(f"Added {padding} '=' characters for base64 padding")
                
        return message
        
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        raise ValueError(f"Failed to decode message: {str(e)}")

# Add capacity estimation functions
def estimate_lsb_capacity(img):
    """Estimate the maximum capacity for LSB method in bytes"""
    pixels = img.size[0] * img.size[1]
    # One bit per pixel, minus 8 bits for null terminator
    max_bits = pixels - 8
    return max_bits // 8  # Convert bits to bytes

def estimate_pvd_capacity(img):
    """Estimate the maximum capacity for PVD method in bytes"""
    width, height = img.size
    # Conservative estimate - average 3 bits per pixel pair
    pixel_pairs = (width * height) // 2
    max_bits = pixel_pairs * 3 - 8  # Minus 8 bits for null terminator
    return max_bits // 8  # Convert bits to bytes

# Add this function to help with encoding message with method selection
def encode_message(img, encrypted_message, method="LSB", debug=False, progress_callback=None):
    """Encode an encrypted message into an image using the specified method"""
    if method not in AVAILABLE_ENCRYPTION_METHODS:
        raise ValueError(f"Unknown encryption method: {method}")
        
    if method == "LSB":
        # Use existing LSB function
        return encode_message_lsb(img, encrypted_message, debug)
    elif method == "PVD":
        # Use PVD function
        return encode_message_pvd(img, encrypted_message, debug, progress_callback)
    elif method == "DWT":
        # Fallback to LSB for now
        logging.warning("DWT method not fully implemented, using LSB instead")
        return encode_message_lsb(img, encrypted_message, debug)
    elif method == "DCT":
        # Fallback to LSB for now
        logging.warning("DCT method not fully implemented, using LSB instead")
        return encode_message_lsb(img, encrypted_message, debug)
    else:
        # Default to LSB
        return encode_message_lsb(img, encrypted_message, debug)

# Add this function for decoding
def decode_message(img, method="LSB", debug=False):
    """
    Extract hidden message from image with improved error handling
    
    Args:
        img: PIL Image object
        method: Steganography method ('LSB', 'PVD', 'DCT', 'DWT')
        debug: Whether to print debug information
    
    Returns:
        The extracted message as bytes, or None if no message is found
    """
    try:
        # First try a brute force approach to find hidden data
        if method == 'AUTO':
            # Try all available methods in sequence
            for m in ['LSB', 'PVD']:
                result = decode_message(img, method=m, debug=debug)
                if result:
                    if debug:
                        logging.debug(f"Successfully extracted message using {m} method")
                    return result
            return None
            
        # Get image dimensions
        width, height = img.size
        max_possible_bits = width * height * 3
        
        if debug:
            logging.debug(f"Decoding with method: {method}, image size: {width}x{height}")
        
        # PVD specific handling with enhanced error recovery
        if method == 'PVD':
            pvd_result = decode_message_pvd(img, debug)
            if pvd_result:
                return pvd_result
                
            # If standard PVD failed, try alternate PVD approach
            alt_pvd_result = decode_message_pvd_alternate(img, debug)
            return alt_pvd_result
        
        # Default/LSB method with more robust extraction
        pixels = list(img.getdata())
        binary = ""
        
        # First extract enough bits to determine length (32 bits)
        pixel_count = min(32, len(pixels)) 
        for i in range(pixel_count):
            if i < len(pixels):
                r, g, b = pixels[i]
                binary += str(r & 1)
                binary += str(g & 1)
                binary += str(b & 1)
                
                if len(binary) >= 32:
                    binary = binary[:32]
                    break
        
        # Parse length with extra validation
        try:
            message_length = int(binary[:32], 2)
            
            if debug:
                logging.debug(f"Detected message length: {message_length} bits")
                
            # Validate length is reasonable (not too large or negative)
            if message_length <= 0:
                if debug:
                    logging.error(f"Invalid negative message length: {message_length}")
                # Try without length header - assume standard message
                return decode_message_without_header(img, debug)
                
            if message_length > max_possible_bits:
                if debug:
                    logging.error(f"Message length too large: {message_length} > {max_possible_bits}")
                # Try with a smaller reasonable length
                message_length = min(max_possible_bits // 2, 8192)  # Cap at reasonable value
                if debug:
                    logging.debug(f"Using capped length instead: {message_length}")
        except ValueError:
            if debug:
                logging.error(f"Could not parse length from: {binary[:32]}")
            # Try without length header
            return decode_message_without_header(img, debug)
            
        # Now extract message bits
        binary = ""
        bits_per_pixel = 3  # RGB channels, 1 bit per channel
        pixels_needed = (message_length + bits_per_pixel - 1) // bits_per_pixel + 32  # +32 for header
        
        for i in range(32, min(pixels_needed, len(pixels))):
            r, g, b = pixels[i]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
            
            if len(binary) >= message_length:
                binary = binary[:message_length]
                break
        
        if debug:
            logging.debug(f"Extracted {len(binary)} bits of data")
            
        # Convert bits to bytes with resilient approach
        message_bytes = bytearray()
        for i in range(0, len(binary), 8):
            if i + 8 <= len(binary):
                try:
                    byte_val = int(binary[i:i+8], 2)
                    message_bytes.append(byte_val)
                except ValueError:
                    if debug:
                        logging.error(f"Invalid byte at position {i}: {binary[i:i+8]}")
                    # Use placeholder for invalid bytes
                    message_bytes.append(0)
        
        if len(message_bytes) == 0:
            if debug:
                logging.error("No message bytes extracted")
            # Try without length header as last resort
            return decode_message_without_header(img, debug)
        
        # Check if the message bytes look like base64 (common for encrypted data)
        message_str = message_bytes.decode('ascii', errors='ignore')
        if any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in message_str):
            if debug:
                logging.warning("Message doesn't look like valid base64, might be corrupt")
        
        return bytes(message_bytes)
        
    except Exception as e:
        if debug:
            logging.exception(f"Error decoding message: {e}")
        # Try simpler methods as fallback
        try:
            return decode_message_without_header(img, debug)
        except:
            return None

def decode_message_without_header(img, debug=False):
    """
    Try to extract a message without relying on a length header
    Simple brute force approach looking for base64-like content
    """
    try:
        if debug:
            logging.debug("Trying to decode without length header")
            
        pixels = list(img.getdata())
        
        # Fixed extraction - 2KB should be enough for most messages
        extract_bits = 16384  # 2KB = 16384 bits
        binary = ""
        
        for i in range(32, min(32 + (extract_bits // 3) + 100, len(pixels))):
            r, g, b = pixels[i]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
            
            if len(binary) >= extract_bits:
                binary = binary[:extract_bits]
                break
                
        # Convert all bits to bytes
        message_bytes = bytearray()
        for i in range(0, len(binary), 8):
            if i + 8 <= len(binary):
                try:
                    byte_val = int(binary[i:i+8], 2)
                    message_bytes.append(byte_val)
                except ValueError:
                    continue
                    
        # Look for the start of base64 data
        message_text = message_bytes.decode('ascii', errors='ignore')
        
        # Basic base64 pattern (simplified)
        import re
        # Look for sequences that could be base64 (letters, numbers, +, /, and =)
        base64_pattern = re.compile(r'[A-Za-z0-9+/=]{16,}')
        matches = base64_pattern.findall(message_text)
        
        if matches:
            if debug:
                logging.debug(f"Found potential base64 data: {len(matches[0])} chars")
            # Use the longest match
            longest_match = max(matches, key=len)
            # Convert back to bytes
            return longest_match.encode('ascii')
            
        # If we found any data at all, return it
        if len(message_bytes) > 0:
            if debug:
                logging.debug(f"Returning raw extracted data: {len(message_bytes)} bytes")
            return bytes(message_bytes)
            
        return None
        
    except Exception as e:
        if debug:
            logging.exception(f"Error in headerless decoding: {e}")
        return None

# Add an alternate PVD method that uses a different approach
def decode_message_pvd_alternate(img, debug=False):
    """Alternative PVD decoding approach focusing on channel differences"""
    try:
        if debug:
            logging.debug("Starting alternate PVD decoding")
            
        # Process image data
        pixels = list(img.getdata())
        width, height = img.size
        
        # Extract bits from the differences between adjacent pixels
        binary_data = ""
        
        # Start after potential header area
        for i in range(32, min(3000, len(pixels)-1)):
            # Compare with next pixel
            r1, g1, b1 = pixels[i]
            r2, g2, b2 = pixels[i+1]
            
            # Extract LSB from channel differences
            r_diff = abs(r1 - r2)
            g_diff = abs(g1 - g2)
            b_diff = abs(b1 - b2)
            
            binary_data += str(r_diff & 1)
            binary_data += str(g_diff & 1)
            binary_data += str(b_diff & 1)
            
            if len(binary_data) >= 1024 * 8:  # Limit to reasonable size
                break
                
        # Convert to bytes
        message_bytes = bytearray()
        for i in range(0, len(binary_data), 8):
            if i + 8 <= len(binary_data):
                try:
                    byte = int(binary_data[i:i+8], 2)
                    message_bytes.append(byte)
                except ValueError:
                    continue
        
        if len(message_bytes) == 0:
            if debug:
                logging.debug("No message bytes extracted with alternate PVD method")
            return None
        
        # Try to find valid base64 content
        try:
            message_text = message_bytes.decode('ascii', errors='ignore')
            import re
            base64_pattern = re.compile(r'[A-Za-z0-9+/=]{16,}')
            matches = base64_pattern.findall(message_text)
            
            if matches:
                longest_match = max(matches, key=len)
                if debug:
                    logging.debug(f"Found potential base64 data with alternate PVD: {len(longest_match)} chars")
                return longest_match.encode('ascii')
        except:
            pass
            
        # Return all extracted data
        if debug:
            logging.debug(f"Extracted {len(message_bytes)} bytes with alternate PVD method")
        return bytes(message_bytes)
        
    except Exception as e:
        if debug:
            logging.exception(f"Error in alternate PVD decoding: {e}")
        return None

def decrypt_message(ciphertext, password, debug=False):
    """
    Decrypt a message using AES-GCM with enhanced padding error handling
    
    Args:
        ciphertext: The encrypted message as bytes
        password: The encryption password
        debug: Whether to print debug information
    
    Returns:
        The decrypted message as a string
    """
    try:
        if debug:
            logging.debug(f"Decrypting message of length {len(ciphertext)}")
            
        # Generate key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        
        # Extract nonce and ciphertext
        nonce = ciphertext[:12]
        tag = ciphertext[-16:]
        encrypted_data = ciphertext[12:-16]
        
        if debug:
            logging.debug(f"Nonce length: {len(nonce)}, Tag length: {len(tag)}, Data length: {len(encrypted_data)}")
        
        # Decrypt
        cipher = AESGCM(key)
        try:
            decrypted_data = cipher.decrypt(nonce, encrypted_data + tag, None)
            
            # Add padding handling
            if debug:
                logging.debug(f"Decrypted data length: {len(decrypted_data)}")
            
            # Try to decode as UTF-8
            try:
                result = decrypted_data.decode('utf-8')
                return result
            except UnicodeDecodeError as e:
                if debug:
                    logging.error(f"Unicode decode error: {str(e)}")
                
                # Try different encodings
                for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        return decrypted_data.decode(encoding)
                    except UnicodeDecodeError:
                        continue
                
                # Last resort: return as hex string
                return decrypted_data.hex()
                
        except Exception as e:
            if debug:
                logging.error(f"Error decrypting message: {str(e)}")
            raise ValueError(f"{str(e)}")
            
    except Exception as e:
        if debug:
            logging.error(f"Error in decrypt_message: {str(e)}")
        raise ValueError(f"{str(e)}")

# Add this new function to handle PVD decoding specifically
def decode_message_pvd(img, debug=False):
    """
    Extract hidden message from image using PVD method with improved error handling
    """
    try:
        if debug:
            logging.debug("Starting PVD decoding")
            
        width, height = img.size
        pixels = list(img.getdata())
        
        # Get message length from first part of image
        binary_length = ""
        for i in range(32): # First 32 pixels for length (32 bits)
            r1, g1, b1 = pixels[i]
            r2, g2, b2 = pixels[i+1] if i+1 < len(pixels) else (0,0,0)
            
            # Get LSB of differences
            diff_r = abs(r1 - r2)
            binary_length += str(diff_r & 1)
            
            diff_g = abs(g1 - g2)
            binary_length += str(diff_g & 1)
            
            diff_b = abs(b1 - b2)
            binary_length += str(diff_b & 1)
            
            if len(binary_length) >= 32:
                binary_length = binary_length[:32]
                break
        
        # Convert binary length to int
        message_length_bits = int(binary_length, 2)
        
        if debug:
            logging.debug(f"Decoded message length: {message_length_bits} bits")
            
        if message_length_bits <= 0 or message_length_bits > width * height * 3:
            if debug:
                logging.error(f"Invalid message length: {message_length_bits}")
            return None
            
        # Calculate bytes needed
        bytes_needed = (message_length_bits + 7) // 8
        
        if debug:
            logging.debug(f"Extracting {bytes_needed} bytes from image")
            
        # Extract message
        binary_message = ""
        for i in range(32, 32 + message_length_bits // 3 + 2): # Start after length bits
            if i >= len(pixels) - 1:
                break
                
            r1, g1, b1 = pixels[i]
            r2, g2, b2 = pixels[i+1]
            
            # LSB of differences
            diff_r = abs(r1 - r2)
            binary_message += str(diff_r & 1)
            
            diff_g = abs(g1 - g2)
            binary_message += str(diff_g & 1)
            
            diff_b = abs(b1 - b2)
            binary_message += str(diff_b & 1)
            
            if len(binary_message) >= message_length_bits:
                binary_message = binary_message[:message_length_bits]
                break
                
        # Convert to bytes
        message_bytes = bytearray()
        for i in range(0, len(binary_message), 8):
            if i + 8 <= len(binary_message):
                byte = binary_message[i:i+8]
                message_bytes.append(int(byte, 2))
        
        if debug:
            logging.debug(f"Extracted {len(message_bytes)} bytes")
            
        return bytes(message_bytes)
        
    except Exception as e:
        if debug:
            logging.exception(f"PVD decoding error: {e}")
        return None

# Update the decode_message function to handle invalid message lengths
def decode_message(img, method='LSB', debug=False):
    """
    Extract hidden message from image with improved error handling and validation
    
    Args:
        img: PIL Image object
        method: Steganography method ('LSB', 'PVD', 'DCT', 'DWT')
        debug: Whether to print debug information
    
    Returns:
        The extracted message as bytes, or None if no message is found
    """
    try:
        width, height = img.size
        max_possible_length = width * height * 3  # Maximum possible bits in the image
        
        if debug:
            logging.debug(f"Decoding image with method: {method}, image size: {width}x{height}")
            
        # PVD specific handling
        if method == 'PVD':
            return decode_message_pvd(img, debug)
        
        # Default/LSB method
        binary = ""
        
        # Extract the first 32 bits for length
        pixels = list(img.getdata())
        
        # Extract length
        for i in range(min(32, len(pixels))):
            r, g, b = pixels[i]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
            
            if len(binary) >= 32:
                binary = binary[:32]
                break
        
        # Get message length with validation
        try:
            message_length = int(binary[:32], 2)
            if debug:
                logging.debug(f"Message length in bits: {message_length}")
                
            # Add stronger validation for message length
            if message_length <= 0 or message_length > max_possible_length:
                if debug:
                    logging.error(f"Invalid message length: {message_length}")
                return None
                
        except ValueError:
            if debug:
                logging.error(f"Invalid length binary: {binary[:32]}")
            return None
            
        # Now extract the actual message
        binary = ""
        for i in range(32, len(pixels)):
            r, g, b = pixels[i]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
            
            if len(binary) >= message_length:
                binary = binary[:message_length]
                break
        
        # Convert binary to bytes with extra validation
        message_bytes = bytearray()
        for i in range(0, len(binary), 8):
            if i + 8 <= len(binary):
                byte = binary[i:i+8]
                try:
                    message_bytes.append(int(byte, 2))
                except ValueError:
                    if debug:
                        logging.error(f"Invalid byte at position {i}: {byte}")
                    continue
        
        if len(message_bytes) == 0:
            if debug:
                logging.error("No message bytes extracted")
            return None
            
        return bytes(message_bytes)
            
    except Exception as e:
        if debug:
            logging.exception(f"Error decoding message: {e}")
        return None

def direct_lsb_decode(img, debug=False):
    """
    Direct LSB decoding without relying on length header
    Extracts message directly looking for valid base64 patterns
    """
    if debug:
        logging.debug("Starting direct LSB decoding")

    try:
        # Get image dimensions and pixels
        width, height = img.size
        pixels = list(img.getdata())
        
        # We'll extract a reasonable amount of data directly
        extracted_bits = []
        
        # First extract bits from the first ~4KB of the image (enough for most messages)
        max_pixels = min(4096, len(pixels))
        
        for i in range(max_pixels):
            r, g, b = pixels[i]
            extracted_bits.extend([r & 1, g & 1, b & 1])
            
        # Convert bits to bytes
        message_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            if i + 8 <= len(extracted_bits):
                byte_val = 0
                for j in range(8):
                    byte_val |= extracted_bits[i+j] << (7-j)
                message_bytes.append(byte_val)
        
        # Convert to string for analysis
        message_str = message_bytes.decode('ascii', errors='ignore')
        
        # Look for base64 patterns
        import re
        base64_pattern = re.compile(r'[A-Za-z0-9+/=]{16,}')
        matches = base64_pattern.findall(message_str)
        
        if matches:
            # Find the longest match that could be base64
            candidates = []
            for match in matches:
                # Check if it's a valid base64 string length (multiple of 4)
                if len(match) % 4 == 0:
                    candidates.append(match)
                # Or can be made valid with padding
                elif len(match) % 4 != 0:
                    # Add padding to make it a multiple of 4
                    padding_needed = 4 - (len(match) % 4)
                    padded_match = match + '=' * padding_needed
                    candidates.append(padded_match)
                    
            if candidates:
                longest_match = max(candidates, key=len)
                if debug:
                    logging.debug(f"Found base64 candidate: {longest_match[:20]}... ({len(longest_match)} chars)")
                return longest_match.encode('ascii')
            
        if debug:
            logging.debug("No valid base64 data found in direct LSB extraction")
            
        # Last resort: return the raw bytes if they look like they might contain useful data
        if any(c >= 32 and c <= 126 for c in message_bytes[:100]):  # Check if there are printable ASCII chars
            if debug:
                logging.debug(f"Returning raw extracted bytes with printable ASCII chars")
            return message_bytes
        
        return None
    except Exception as e:
        if debug:
            logging.exception(f"Error in direct LSB decoding: {e}")
        return None

# Update the decode_message function to use our new direct LSB approach
def decode_message(img, method='LSB', debug=False):
    """
    Extract hidden message from image with improved error handling and fallback methods
    """
    try:
        # First try direct decoding for speed
        if method == 'AUTO' or method == 'LSB':
            if debug:
                logging.debug("Trying direct LSB decoding first")
            result = direct_lsb_decode(img, debug)
            if result:
                return result
        
        # Then try standard approaches
        width, height = img.size
        max_possible_bits = width * height * 3
        
        if debug:
            logging.debug(f"Falling back to standard decoding with method: {method}")
        
        # Try each method in sequence for AUTO mode
        if method == 'AUTO':
            for m in ['LSB', 'PVD']:
                try:
                    if debug:
                        logging.debug(f"Trying method: {m}")
                    if m == 'PVD':
                        result = decode_message_pvd(img, debug)
                    else:
                        result = decode_message_lsb(img, debug)
                    
                    if result:
                        return result
                except Exception as method_err:
                    if debug:
                        logging.warning(f"Method {m} failed: {str(method_err)}")
        
        # Otherwise use specified method
        if method == 'LSB':
            return decode_message_lsb(img, debug)
        elif method == 'PVD':
            return decode_message_pvd(img, debug)
        
        # If nothing worked, try headerless decoding as last resort
        if debug:
            logging.debug("Trying headerless decoding as last resort")
        return decode_message_without_header(img, debug)
            
    except Exception as e:
        if debug:
            logging.exception(f"Error in decode_message: {e}")
        # Last chance - try headerless
        try:
            return decode_message_without_header(img, debug)
        except:
            return None