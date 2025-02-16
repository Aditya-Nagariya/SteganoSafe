import os
import base64
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_message(message, password):
    if not message or not password:
        raise ValueError("Message and password are required")
    key, salt = generate_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_message = aesgcm.encrypt(nonce, message.encode(), None)
    combined = salt + nonce + encrypted_message
    return base64.urlsafe_b64encode(combined).decode('utf-8')

def encode_message(image, message):
    img_array = np.array(image).astype(np.uint8)
    # Convert message to binary and append a null delimiter
    binary_message = ''.join(format(ord(c), '08b') for c in message) + '00000000'
    if len(binary_message) > img_array.size:
        raise ValueError("Message too large for this image")
    idx = 0
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            for k in range(3):  # RGB channels
                if idx < len(binary_message):
                    bit = int(binary_message[idx])
                    img_array[i, j, k] = (img_array[i, j, k] & ~1) | bit
                    idx += 1
    return Image.fromarray(img_array)

# Added functions for decryption and decoding
def decode_message(image):
    try:
        img_array = np.array(image)
        binary_message = ''
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for k in range(3):
                    binary_message += str(img_array[i, j, k] & 1)
                    if len(binary_message) % 8 == 0:
                        if chr(int(binary_message[-8:], 2)) == '\0':
                            message = ''
                            for idx in range(0, len(binary_message) - 8, 8):
                                message += chr(int(binary_message[idx:idx+8], 2))
                            return message
        return None
    except Exception as e:
        logging.error(f"Decoding error: {str(e)}")
        return None

def decrypt_message(encoded_message, password):
    try:
        combined = base64.urlsafe_b64decode(encoded_message.encode('utf-8'))
        salt = combined[:16]
        nonce = combined[16:28]
        ciphertext = combined[28:]
        key, _ = generate_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        raise ValueError("Invalid password or corrupted message")
