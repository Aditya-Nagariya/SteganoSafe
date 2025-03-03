"""
Steganography module for hiding and extracting encrypted messages in images
using the Least Significant Bit (LSB) technique.
"""
import numpy as np
from PIL import Image
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import logging

def encrypt_message(message, password):
    """
    Encrypt a message using the password
    
    Args:
        message (str): Message to encrypt
        password (str): Password for encryption
        
    Returns:
        str: Base64-encoded encrypted message
    """
    if not message:
        raise ValueError("Message cannot be empty")
    if not password:
        raise ValueError("Password cannot be empty")
        
    # Convert message and password to bytes
    message_bytes = message.encode('utf-8')
    password_bytes = password.encode('utf-8')
    
    # Generate a key from the password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    
    # Encrypt the message
    f = Fernet(key)
    encrypted_message = f.encrypt(message_bytes)
    
    # Return the salt + encrypted message, base64 encoded
    result = base64.urlsafe_b64encode(salt + encrypted_message).decode('utf-8')
    return result

def decrypt_message(encrypted_data, password):
    """
    Decrypt a message using the password
    
    Args:
        encrypted_data (str): Base64-encoded encrypted message
        password (str): Password for decryption
        
    Returns:
        str: Decrypted message
    """
    if not encrypted_data:
        raise ValueError("Encrypted data cannot be empty")
    if not password:
        raise ValueError("Password cannot be empty")
    
    try:
        # Decode the base64 data
        data = base64.urlsafe_b64decode(encrypted_data)
        
        # Extract the salt (first 16 bytes)
        salt = data[:16]
        encrypted_message = data[16:]
        
        # Derive the key using the same parameters as during encryption
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        # Decrypt the message
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        
        return decrypted_message.decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        raise ValueError("Decryption failed. Incorrect password or corrupted data.")

def encode_message(image, message):
    """
    Encode a message into an image using LSB steganography
    
    Args:
        image (PIL.Image): Image to hide the message in
        message (str): Message to hide (should be encrypted)
        
    Returns:
        PIL.Image: New image with the hidden message
    """
    # Convert the image to numpy array
    img_array = np.array(image)
    
    # Get image dimensions and calculate capacity
    height, width, channels = img_array.shape
    max_bytes = (height * width * channels) // 8  # Each byte needs 8 bits
    
    # Add some overhead for the terminator
    message_size = len(message) + 1  # +1 for null terminator
    
    # Check if image is large enough
    if message_size > max_bytes:
        raise ValueError(f"Message too large for this image. Maximum size: {max_bytes-1} bytes, message size: {len(message)} bytes")
    
    # Convert message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_message += '00000000'  # Add NULL terminator
    
    # Flatten the image
    flat_img = img_array.flatten()
    
    # Modified approach to avoid overflow
    for i, bit in enumerate(binary_message):
        if i >= len(flat_img):
            break
            
        # Use NumPy's bitwise operations which handle uint8 correctly
        # Clear the LSB by ANDing with 254 (binary: 11111110)
        # Then set it to the new bit value
        if int(bit) == 1:
            flat_img[i] = (flat_img[i] & 254) | 1  # Set LSB to 1
        else:
            flat_img[i] = (flat_img[i] & 254)  # Set LSB to 0
    
    # Reshape back to original dimensions
    stego_img = flat_img.reshape(img_array.shape)
    
    # Convert back to PIL Image
    return Image.fromarray(stego_img.astype(np.uint8))

def decode_message(image):
    """
    Extract a message from an image using LSB steganography
    
    Args:
        image (PIL.Image): Image containing the hidden message
        
    Returns:
        str: Extracted message
    """
    # Convert to numpy array
    img_array = np.array(image)
    
    # Flatten the array
    flat_img = img_array.flatten()
    
    # Extract LSBs
    binary_message = ''.join(str(pixel & 1) for pixel in flat_img)
    
    # Convert binary to ASCII (8 bits per character)
    message = ""
    for i in range(0, len(binary_message), 8):
        if i + 8 > len(binary_message):
            break
            
        byte = binary_message[i:i+8]
        # Stop at null terminator
        if byte == '00000000':
            break
            
        message += chr(int(byte, 2))
    
    return message if message else None
