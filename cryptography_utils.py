"""
Advanced cryptography utilities for SteganoSafe
WARNING: Some functions in this file bypass cryptographic security measures
and should only be used for data recovery purposes.
"""
import logging
import traceback
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
        logger.debug(f"Attempting raw AES-GCM decryption with key length {len(key)}")
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
        logger.error(traceback.format_exc())
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
        except Exception as e:
            logger.debug(f"Password variant '{password}' failed: {e}")
            continue
    
    return False, None, None

def emergency_recover_message(data, password):
    """
    Last resort function to recover encrypted data
    
    Args:
        data: The encrypted data
        password: The password to try
        
    Returns:
        The recovered text or None if recovery failed
    """
    logger.debug("Attempting emergency message recovery")
    
    try:
        # If data is a base64 string, decode it
        if isinstance(data, str):
            try:
                data = base64.b64decode(data)
            except:
                # If it's not valid base64, just use it as is
                data = data.encode('utf-8')
                
        # Try different key derivation methods
        for salt in [b'SteganoSafeDefaultSalt2023!', b'\x00' * 16]:
            for key_length in [32, 16]:  # Try AES-256 and AES-128
                for iterations in [100000, 10000, 1000]:  # Try different iteration counts
                    try:
                        # Derive a key
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=key_length,
                            salt=salt,
                            iterations=iterations,
                            backend=default_backend()
                        )
                        key = kdf.derive(password.encode())
                        
                        # Try different parts of the data as the encrypted content
                        data_chunks = []
                        
                        # If data is long enough, try various segments
                        if len(data) > 44:  # 16 (salt) + 12 (nonce) + 16 (minimum data)
                            # Standard format: salt + nonce + data + tag
                            data_chunks.append((data[16:28], data[28:-16], data[-16:]))
                            
                            # Alternative format: nonce + data + tag
                            data_chunks.append((data[:12], data[12:-16], data[-16:]))
                            
                            # Just guess based on reasonable positions
                            data_chunks.append((data[:12], data[12:], b''))
                            data_chunks.append((data[16:28], data[28:], b''))
                        else:
                            # For short data, just try what we have
                            if len(data) > 16:
                                data_chunks.append((data[:12], data[12:], b''))
                            else:
                                # Too short, but try anyway
                                data_chunks.append((data[:4], data[4:], b''))
                        
                        for nonce, ctext, tag in data_chunks:
                            try:
                                # Try ECB mode (no nonce needed)
                                if len(ctext) % 16 == 0:  # Must be multiple of 16 bytes
                                    ecb_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
                                    ecb_decryptor = ecb_cipher.decryptor()
                                    plaintext = ecb_decryptor.update(ctext) + ecb_decryptor.finalize()
                                    
                                    # Check if result contains printable ASCII
                                    printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in plaintext)
                                    
                                    # If it has some reasonable text, return it
                                    if sum(c.isalpha() for c in printable) > len(printable) / 5:
                                        return f"[EMERGENCY RECOVERY] {printable}"
                                
                                # Try CTR mode
                                if len(nonce) > 0:
                                    # Pad/truncate nonce to 16 bytes for CTR mode
                                    if len(nonce) < 16:
                                        nonce = nonce + b'\x00' * (16 - len(nonce))
                                    else:
                                        nonce = nonce[:16]
                                        
                                    ctr_cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
                                    ctr_decryptor = ctr_cipher.decryptor()
                                    plaintext = ctr_decryptor.update(ctext) + ctr_decryptor.finalize()
                                    
                                    # Check if result contains printable ASCII
                                    printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in plaintext)
                                    
                                    # If it has some reasonable text, return it
                                    if sum(c.isalpha() for c in printable) > len(printable) / 5:
                                        return f"[EMERGENCY RECOVERY] {printable}"
                            except Exception:
                                # Just continue to the next option
                                continue
                    except Exception:
                        # Continue to the next parameter combination
                        continue
        
        return None
    except Exception as e:
        logger.error(f"Emergency recovery failed: {e}")
        logger.error(traceback.format_exc())
        return None

# Additional testing function
def test_decrypt(ciphertext, password):
    """
    Test function to decrypt data with full logging of all steps
    
    Args:
        ciphertext: The encrypted data as bytes or base64 string
        password: The password to decrypt with
        
    Returns:
        A dictionary with the decryption results and debug info
    """
    results = {'success': False, 'methods_tried': []}
    
    try:
        # If input is string, try base64 decode
        if isinstance(ciphertext, str):
            try:
                ciphertext = base64.b64decode(ciphertext)
                results['methods_tried'].append('base64_decode')
            except Exception as e:
                results['base64_error'] = str(e)
                # Continue with the string as bytes
                ciphertext = ciphertext.encode('utf-8')
                
        # Get salt, nonce, and encrypted data
        if len(ciphertext) >= 28:
            salt = ciphertext[:16]
            nonce = ciphertext[16:28] 
            tag = ciphertext[-16:]
            encrypted_data = ciphertext[28:-16]
            
            results['data_info'] = {
                'total_length': len(ciphertext),
                'salt_length': len(salt),
                'nonce_length': len(nonce),
                'tag_length': len(tag),
                'encrypted_data_length': len(encrypted_data)
            }
            
            # Try standard derivation
            results['methods_tried'].append('standard_key_derivation')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            results['key_info'] = {'length': len(key)}
            
            # Try with AES-GCM
            results['methods_tried'].append('aes_gcm')
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                cipher = AESGCM(key)
                plaintext = cipher.decrypt(nonce, encrypted_data + tag, None)
                results['success'] = True
                results['plaintext'] = plaintext.decode('utf-8', errors='replace')
                results['method_success'] = 'aes_gcm'
                return results
            except Exception as e:
                results['aes_gcm_error'] = str(e)
            
            # Try raw AES decryption
            results['methods_tried'].append('raw_aes_gcm')
            try:
                plaintext = raw_aes_gcm_decrypt(key, nonce, encrypted_data, tag)
                if plaintext:
                    results['success'] = True
                    results['plaintext'] = plaintext.decode('utf-8', errors='replace')
                    results['method_success'] = 'raw_aes_gcm'
                    return results
            except Exception as e:
                results['raw_aes_gcm_error'] = str(e)
            
            # Try emergency recovery
            results['methods_tried'].append('emergency_recover')
            try:
                recovery = emergency_recover_message(ciphertext, password)
                if recovery:
                    results['success'] = True
                    results['plaintext'] = recovery
                    results['method_success'] = 'emergency_recover'
                    return results
            except Exception as e:
                results['emergency_recover_error'] = str(e)
                
        return results
    except Exception as e:
        results['error'] = str(e)
        return results
