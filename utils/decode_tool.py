"""
Command-line utility to help diagnose and recover steganography images
with decryption problems.

Usage:
    python decode_tool.py <image_path> [options]

Options:
    --password PASSWORD    Password to use for decryption
    --method METHOD        Decoding method (LSB, PVD, AUTO)
    --bypass-auth          Try to bypass authentication tag validation
    --recovery             Enable all recovery methods
    --output OUTPUT        Output file to save decrypted content
"""
import os
import sys
import logging
import argparse
import traceback
from PIL import Image

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("decode_tool")

# Add parent directory to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

def debug_image(image_path):
    """Print debug information about an image"""
    try:
        from PIL import Image
        img = Image.open(image_path)
        
        print("\n===== IMAGE DEBUG INFO =====")
        print(f"Filename: {os.path.basename(image_path)}")
        print(f"Format: {img.format}")
        print(f"Size: {img.size}")
        print(f"Mode: {img.mode}")
        
        # Print file size
        file_size = os.path.getsize(image_path)
        print(f"File size: {file_size} bytes ({file_size/1024:.2f} KB)")
        
        # Print first few pixels for debugging
        pixels = list(img.getdata())[:10]
        print(f"First 10 pixels: {pixels}")
        
        # Check LSB of first few pixels
        print("\nLSB analysis of first 10 pixels:")
        for i, pixel in enumerate(pixels):
            if len(pixel) >= 3:  # RGB or RGBA
                r, g, b = pixel[:3]
                print(f"Pixel {i}: R:{r & 1} G:{g & 1} B:{b & 1}")
        
        return img
    except Exception as e:
        logger.error(f"Error analyzing image: {e}")
        return None
        
def extract_data(img, method="AUTO"):
    """Try to extract hidden data from the image using various methods"""
    try:
        print("\n===== ATTEMPTING DATA EXTRACTION =====")
        print(f"Using method: {method}")
        
        from stego import direct_lsb_decode, decode_message
        
        # Try direct LSB decode first (optimized for base64)
        print("\nAttempting direct_lsb_decode...")
        direct_result = direct_lsb_decode(img, debug=True)
        
        if direct_result:
            print(f"✓ Direct LSB decode successful! Extracted {len(direct_result)} bytes")
            
            # Try to display the first part as string
            try:
                sample = direct_result[:100].decode('ascii', errors='replace')
                print(f"Sample data: {sample}...")
            except Exception:
                pass
                
            return direct_result
            
        # Try standard decoding with the specified method
        print(f"\nAttempting standard decode with method: {method}...")
        standard_result = decode_message(img, method=method, debug=True)
        
        if standard_result:
            print(f"✓ Standard decode successful! Extracted {len(standard_result)} bytes")
            
            # Try to display the first part as string
            try:
                sample = standard_result[:100].decode('ascii', errors='replace')
                print(f"Sample data: {sample}...")
            except Exception:
                pass
                
            return standard_result
            
        print("❌ No hidden data found using standard methods")
        
        # Try desperate measures
        print("\nAttempting last resort extraction methods...")
        
        # Check for ASCII text hidden directly
        try:
            from stego import decode_message_without_header
            raw_result = decode_message_without_header(img, debug=True)
            if raw_result:
                print(f"✓ Found {len(raw_result)} bytes using headerless method")
                return raw_result
        except Exception as e:
            logger.error(f"Headerless decode error: {e}")
            
        return None
    except Exception as e:
        logger.error(f"Extraction error: {e}")
        logger.error(traceback.format_exc())
        return None
        
def attempt_decrypt(encrypted_data, password, bypass_auth=False):
    """Try to decrypt the encrypted data using various methods"""
    try:
        print("\n===== ATTEMPTING DECRYPTION =====")
        print(f"Data length: {len(encrypted_data)} bytes")
        print(f"Bypass auth: {bypass_auth}")
        
        # Try standard decryption first
        try:
            print("\nAttempting standard decryption...")
            from stego import decrypt_message
            decrypted = decrypt_message(encrypted_data, password, debug=True)
            print(f"✓ Decryption successful!")
            return decrypted
        except Exception as e:
            print(f"❌ Standard decryption failed: {e}")
            
        # Try with bypass auth
        if bypass_auth:
            try:
                print("\nAttempting decryption with auth bypass...")
                from stego import decrypt_message
                decrypted = decrypt_message(encrypted_data, password, debug=True, bypass_auth=True)
                print(f"✓ Decryption with auth bypass successful!")
                return f"[RECOVERED] {decrypted}"
            except Exception as e:
                print(f"❌ Auth bypass decryption failed: {e}")
                
        # Try safe decrypt
        try:
            print("\nAttempting safe decryption...")
            from stego import decrypt_message_safe
            decrypted = decrypt_message_safe(encrypted_data, password, debug=True)
            print(f"✓ Safe decryption successful!")
            return decrypted
        except Exception as e:
            print(f"❌ Safe decryption failed: {e}")
            
        # Try password variants
        try:
            print("\nAttempting password variants...")
            from cryptography_utils import attempt_password_variants
            
            def decrypt_wrapper(data, pwd):
                from stego import decrypt_message_safe
                return decrypt_message_safe(data, pwd, debug=True)
                
            success, decrypted, used_password = attempt_password_variants(encrypted_data, password, decrypt_wrapper)
            
            if success:
                print(f"✓ Decrypted with password variant: '{used_password}'")
                return f"[CORRECTED-PASSWORD] {decrypted}"
        except Exception as e:
            print(f"❌ Password variants failed: {e}")
            
        # As a last resort, try emergency recovery
        try:
            print("\nAttempting emergency recovery...")
            from cryptography_utils import emergency_recover_message
            recovered = emergency_recover_message(encrypted_data, password)
            
            if recovered:
                print(f"✓ Emergency recovery successful!")
                return recovered
        except Exception as e:
            print(f"❌ Emergency recovery failed: {e}")
            
        print("\n❌ All decryption attempts failed")
        return None
        
    except Exception as e:
        logger.error(f"Decryption attempts error: {e}")
        logger.error(traceback.format_exc())
        return None

def main():
    """Main entry point for the tool"""
    parser = argparse.ArgumentParser(description="Steganography Debugging Tool")
    parser.add_argument("image", help="Path to the image file")
    parser.add_argument("--password", help="Password for decryption")
    parser.add_argument("--method", choices=["LSB", "PVD", "AUTO"], default="AUTO", help="Decoding method")
    parser.add_argument("--bypass-auth", action="store_true", help="Try bypass auth tag validation")
    parser.add_argument("--recovery", action="store_true", help="Enable all recovery methods")
    parser.add_argument("--output", help="Output file to save decrypted content")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image):
        print(f"Error: Image file '{args.image}' does not exist")
        return 1
        
    print(f"Analyzing image: {args.image}")
    
    # Debug the image
    img = debug_image(args.image)
    if not img:
        return 1
        
    # Extract hidden data from image
    encrypted_data = extract_data(img, args.method)
    
    if not encrypted_data:
        print("Failed to extract any hidden data from the image")
        return 1
        
    # If no password is provided, we can't decrypt
    if not args.password:
        print("\nNo password provided. Use --password to attempt decryption.")
        return 0
        
    # Try to decrypt the data
    decrypted = attempt_decrypt(encrypted_data, args.password, 
                               bypass_auth=args.bypass_auth or args.recovery)
    
    if decrypted:
        print("\n===== DECRYPTION RESULT =====")
        print(decrypted[:1000])  # Show first 1000 chars
        
        # Save to output file if requested
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(decrypted)
                print(f"\nDecrypted content saved to {args.output}")
            except Exception as e:
                print(f"Error saving output: {e}")
                
        return 0
    else:
        print("\nDecryption failed with all available methods.")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)
