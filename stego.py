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

# Setup logging
logger = logging.getLogger(__name__)

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

def encode_message(image, message, debug=False):
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

def decode_message(image, debug=False):
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
