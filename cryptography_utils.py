"""
Advanced cryptography utilities for SteganoSafe
WARNING: Some functions in this file bypass cryptographic security measures
and should only be used for data recovery purposes.
"""
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

def raw_aes_gcm_decrypt(key, nonce, ciphertext, tag, associated_data=None):
    """
    Attempt to decrypt AES-GCM data without tag validation
    
    WARNING: This bypasses authentication and should only be used for recovery
    of corrupted data when the standard decryption fails.
    
    Args:
        key: The AES key (32 bytes for AES-256)
        nonce: The nonce used for encryption (12 bytes)
        ciphertext: The encrypted data
        tag: The authentication tag
        associated_data: Any additional authenticated data
        
    Returns:
        The decrypted data or None if decryption failed
    """
    try:
        # AES-GCM uses counter mode internally
        # We'll implement the decryption part without authentication
        
        # Create a counter mode cipher with the key and nonce
        counter = modes.CTR(nonce + b'\x00\x00\x00\x01')  # Initial counter value for GCM
        cipher = Cipher(algorithms.AES(key), counter, backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Log that we're skipping authentication
        logger.warning("AES-GCM decryption performed without tag validation - data integrity not verified")
        
        return plaintext
    
    except Exception as e:
        logger.error(f"Raw AES-GCM decryption failed: {e}")
        return None

def attempt_password_variants(encrypted_data, base_password, decrypt_function):
    """
    Try common password variants to handle typos or case issues
    
    Args:
        encrypted_data: The encrypted data to decrypt
        base_password: The base password to try variations of
        decrypt_function: A function that takes (data, password) and returns decrypted data
        
    Returns:
        Tuple of (success, decrypted_data, password_used)
    """
    # List of common password variations to try
    passwords_to_try = [
        base_password,                   # Original password
        base_password.lower(),           # All lowercase
        base_password.upper(),           # All uppercase
        base_password.capitalize(),      # First letter capitalized
        base_password + '!',             # Common suffix
        base_password + '1',             # Common number suffix
        ''.join(base_password.split()),  # Remove spaces
    ]
    
    # Add variants with swapped adjacent characters (for typos)
    for i in range(len(base_password) - 1):
        swapped = list(base_password)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        passwords_to_try.append(''.join(swapped))
    
    # Try each password
    for password in passwords_to_try:
        try:
            decrypted = decrypt_function(encrypted_data, password)
            if decrypted:
                return True, decrypted, password
        except:
            continue
    
    return False, None, None
