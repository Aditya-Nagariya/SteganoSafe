"""
Helper functions for encryption and steganography operations
"""
import logging
from typing import List

logger = logging.getLogger(__name__)

def get_available_encryption_methods() -> List[str]:
    """Return a list of available encryption methods"""
    try:
        from stego import AVAILABLE_ENCRYPTION_METHODS
        return AVAILABLE_ENCRYPTION_METHODS
    except Exception as e:
        logger.error(f"Error getting encryption methods: {e}")
        return ["LSB", "PVD", "DCT", "DWT"]  # Default fallback

def get_default_encryption_method() -> str:
    """Return the default encryption method"""
    try:
        from stego import get_default_encryption_method
        return get_default_encryption_method()
    except Exception as e:
        logger.error(f"Error getting default encryption method: {e}")
        return "LSB"  # Default fallback
