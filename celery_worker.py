from app import app, celery, encrypt_message, encode_message
from PIL import Image as PilImage
import numpy as np
import io
import time

@celery.task
def encrypt_task(image_data, password, message):
    img = PilImage.open(io.BytesIO(image_data))
    if img.mode != 'RGB':
        img = img.convert('RGB')
    encrypted_message = encrypt_message(message, password)
    encoded_image = encode_message(img, encrypted_message)
    # Simulate saving the image (e.g. upload to storage or database)
    time.sleep(2)  # simulate heavy processing delay
    # Optionally, emit Socket.IO event for real-time update (requires additional setup)
    return "Encryption completed"
