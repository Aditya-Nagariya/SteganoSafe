"""
Steganography method detection module
This helps detect which steganography method was used on an image
"""

import logging
from PIL import Image
import numpy as np
import re

logger = logging.getLogger(__name__)

def detect_encoding_method(img, debug=False):
    """
    Detect which steganography method was likely used on this image
    
    Args:
        img: PIL Image object
        debug: Whether to print debug info
    
    Returns:
        tuple (method, confidence) where method is one of "LSB", "PVD", "DWT", "DCT"
        and confidence is a value from 0-1
    """
    if debug:
        logger.debug("Starting steganography method detection")
    
    # First, check for method markers by attempting specific decoding
    try:
        from stego import decrypt_lsb
        
        # Try each specific method's password to check for markers
        methods = [
            ("default_pvd_pass", "PVD_ENCODED:", "PVD"),
            ("default_dct_pass", "DCT_ENCODED:", "DCT"),
            ("default_dwt_pass", "DWT_ENCODED:", "DWT")
        ]
        
        for password, marker, method_name in methods:
            try:
                message = decrypt_lsb(img, password)
                if message and message.startswith(marker):
                    if debug:
                        logger.debug(f"Detected {method_name} encoding with marker")
                    return method_name, 1.0  # 100% confidence with marker
            except Exception:
                pass
                
        # If we didn't find any markers, try to analyze the image
        # Convert to numpy array
        img_array = np.array(img)
        
        # Check for LSB patterns
        lsb_score = analyze_lsb_pattern(img_array, debug)
        pvd_score = analyze_pvd_pattern(img_array, debug)
        dwt_score = 0.1  # Not implemented yet
        dct_score = 0.1  # Not implemented yet
        
        # Return the method with highest score
        scores = {
            "LSB": lsb_score,
            "PVD": pvd_score,
            "DWT": dwt_score,
            "DCT": dct_score
        }
        
        best_method = max(scores.items(), key=lambda x: x[1])
        if debug:
            logger.debug(f"Method detection scores: {scores}")
            logger.debug(f"Selected method: {best_method[0]} with confidence {best_method[1]:.2f}")
            
        return best_method
    except Exception as e:
        if debug:
            logger.debug(f"Method detection error: {e}")
        # Default to LSB as it's most common
        return "LSB", 0.5

def analyze_lsb_pattern(img_array, debug=False):
    """Analyze image for LSB encoding patterns"""
    try:
        # Sample a portion of the image
        height, width = img_array.shape[:2]
        sample_size = min(1000, height * width)
        
        # Get random sample of pixels
        sample_y = np.random.randint(0, height, sample_size)
        sample_x = np.random.randint(0, width, sample_size)
        
        # Extract LSBs
        lsbs = []
        for i in range(sample_size):
            pixel = img_array[sample_y[i], sample_x[i]]
            lsbs.extend([pixel[0] & 1, pixel[1] & 1, pixel[2] & 1])
        
        # Look for patterns in LSBs
        # In natural images, LSBs should be roughly 50/50 ones and zeros
        # In LSB steganography, there might be a slight deviation and patterns
        
        # Count ones and zeros
        ones = lsbs.count(1)
        zeros = lsbs.count(0)
        total = len(lsbs)
        
        # Calculate distribution score (closer to 0.5 is more natural)
        distribution = abs(0.5 - (ones / total))
        
        # Calculate a score (higher is more likely to be LSB)
        # Lower distribution difference = higher chance of LSB steganography
        lsb_score = 0.8 - distribution  # 0.8 base score, reduced by distribution abnormality
        
        if debug:
            logger.debug(f"LSB analysis: {ones}/{total} ones ({ones/total:.2f}), distribution diff: {distribution:.4f}")
            logger.debug(f"LSB detection score: {lsb_score:.4f}")
            
        return max(0.1, min(1.0, lsb_score))  # Clamp between 0.1 and 1.0
    except Exception as e:
        if debug:
            logger.debug(f"LSB analysis error: {e}")
        return 0.5  # Default moderate score

def analyze_pvd_pattern(img_array, debug=False):
    """Analyze image for PVD encoding patterns"""
    try:
        # PVD typically modifies pixel value differences
        # We'll check for unusual patterns in pixel value differences
        
        # Sample a portion of the image
        height, width = img_array.shape[:2]
        
        # Calculate horizontal differences
        h_diffs = []
        for y in range(min(height, 100)):
            for x in range(width-1):
                h_diffs.append(abs(int(img_array[y, x, 0]) - int(img_array[y, x+1, 0])))
                h_diffs.append(abs(int(img_array[y, x, 1]) - int(img_array[y, x+1, 1])))
                h_diffs.append(abs(int(img_array[y, x, 2]) - int(img_array[y, x+1, 2])))
        
        # Calculate vertical differences
        v_diffs = []
        for y in range(height-1):
            for x in range(min(width, 100)):
                v_diffs.append(abs(int(img_array[y, x, 0]) - int(img_array[y+1, x, 0])))
                v_diffs.append(abs(int(img_array[y, x, 1]) - int(img_array[y+1, x, 1])))
                v_diffs.append(abs(int(img_array[y, x, 2]) - int(img_array[y+1, x, 2])))
        
        # In PVD, there might be more even-valued differences than in natural images
        even_h = sum(1 for d in h_diffs if d % 2 == 0)
        even_v = sum(1 for d in v_diffs if d % 2 == 0)
        
        h_ratio = even_h / len(h_diffs) if h_diffs else 0.5
        v_ratio = even_v / len(v_diffs) if v_diffs else 0.5
        
        # PVD typically results in more even differences (but not too many)
        # Natural: about 50% even differences
        # PVD: often 55-70% even differences
        h_score = 1.0 - abs(0.6 - h_ratio) * 2  # Score highest around 60% even
        v_score = 1.0 - abs(0.6 - v_ratio) * 2
        
        pvd_score = (h_score + v_score) / 2
        
        if debug:
            logger.debug(f"PVD analysis: H even: {h_ratio:.2f}, V even: {v_ratio:.2f}")
            logger.debug(f"PVD detection score: {pvd_score:.4f}")
            
        return max(0.1, min(1.0, pvd_score))  # Clamp between 0.1 and 1.0
    except Exception as e:
        if debug:
            logger.debug(f"PVD analysis error: {e}")
        return 0.3  # Default low-moderate score for PVD
