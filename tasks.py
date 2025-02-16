from stego import encrypt_message, encode_message
from celery import current_app as celery_app
from PIL import Image as PilImage
import io
import time
import logging

@celery_app.task
def encrypt_task(image_data, password, message):
    try:
        img = PilImage.open(io.BytesIO(image_data))
        if img.mode != 'RGB':
            img = img.convert('RGB')
        # Encrypt and encode the message
        encrypted_message = encrypt_message(message, password)
        encoded_img = encode_message(img, encrypted_message)
        # Optionally save or further process the encoded image
        time.sleep(2)  # Simulate delay
        return "Encryption completed"
    except Exception as e:
        logging.error(f"Error in encrypt_task: {str(e)}")
        raise e
