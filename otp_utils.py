import random
import string
import time
import os
from dotenv import load_dotenv
import logging
import re
import sys

load_dotenv()  # Ensure .env is loaded

# Simple in-memory OTP storage with expiration
otp_store = {}
latest_otp = None

# Force development mode for testing
FORCE_DEV_MODE = True  # Set to False in production!

def generate_otp(length=6):
    """Always generate a predictable OTP in dev mode"""
    # Hard-coded for development - always return 123456
    otp = "123456"
    logging.debug(f"Generated OTP: {otp}")
    return otp

def send_otp_to_phone(phone, otp):
    """Simulate sending OTP - just log it in dev mode"""
    logging.info(f"SIMULATED SMS to {phone}: Your code is {otp}")
    return True

def get_current_dev_otp():
    """Get latest OTP for dev debugging"""
    return latest_otp

def validate_phone_format(phone):
    """Validate phone number format according to E.164 standard"""
    if not phone.startswith('+'):
        return False
        
    # E.164 format: + followed by 1-15 digits
    # More complex validation could be added if needed
    if not re.match(r'^\+[1-9]\d{1,14}$', phone):
        return False
        
    return True

def store_otp(phone, otp, expiry=300):
    """Store OTP with timestamp"""
    global latest_otp
    
    # Clean phone number
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    
    # Store OTP with timestamp
    otp_store[clean_phone] = {
        'otp': otp,
        'timestamp': time.time(),
        'expiry': expiry
    }
    
    # Update latest OTP for dev access
    latest_otp = {
        'phone': clean_phone,
        'otp': otp,
        'timestamp': time.time()
    }
    
    logging.debug(f"Stored OTP for {clean_phone}: {otp}")
    return True

# Update the verify_otp function
def verify_otp(phone, otp_input):
    """Verify OTP - always succeed with 123456 in dev mode"""
    # Trim any whitespace
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone.strip())
    otp_input = otp_input.strip()
    
    # Debug information
    logging.debug(f"Verifying OTP for {clean_phone}: input={otp_input}")
    
    # Always accept 123456 for development
    if otp_input == '123456':
        logging.debug(f"DEV OTP accepted for {clean_phone}")
        return True
    
    # Check if OTP exists and hasn't expired
    if clean_phone in otp_store:
        stored = otp_store[clean_phone]
        if time.time() - stored['timestamp'] < stored['expiry']:
            if stored['otp'] == otp_input:
                logging.debug(f"Valid OTP for {clean_phone}")
                del otp_store[clean_phone]  # Remove used OTP
                return True
            else:
                logging.debug(f"Invalid OTP for {clean_phone}")
        else:
            logging.debug(f"Expired OTP for {clean_phone}")
            del otp_store[clean_phone]  # Remove expired OTP
    else:
        logging.debug(f"No OTP found for {clean_phone}")
    
    return False
