#!/usr/bin/env python
"""
Script to create simple favicons for the SteganoSafe app
"""
import os
import logging
from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)

def create_simple_favicon(output_directory=None, text='S', bg_color=(13, 110, 253), text_color=(255, 255, 255)):
    """Create a simple favicon with the specified text and colors"""
    if not output_directory:
        # Default to the static/img directory
        output_directory = os.path.join(os.path.dirname(__file__), 'static', 'img')
    
    # Create directory if it doesn't exist
    os.makedirs(output_directory, exist_ok=True)
    
    # Create a 32x32 image (good size for favicon)
    img = Image.new('RGB', (256, 256), color=bg_color)
    draw = ImageDraw.Draw(img)
    
    # Try to use a font or fall back to default
    try:
        # Try to find a font to use (system dependent)
        font_paths = [
            '/System/Library/Fonts/Helvetica.ttc',  # macOS
            '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',  # Linux
            'C:/Windows/Fonts/Arial.ttf',  # Windows
            '/usr/share/fonts/TTF/DejaVuSans-Bold.ttf',  # Some Linux distros
        ]
        
        font = None
        for path in font_paths:
            if os.path.exists(path):
                try:
                    font = ImageFont.truetype(path, 160)
                    break
                except Exception:
                    pass
        
        # If no system font works, use default
        if font is None:
            font = ImageFont.load_default()
            # Default font is small, so make the text position more centered
            text_width, text_height = draw.textsize(text)
            position = ((256 - text_width) // 2, (256 - text_height) // 2)
        else:
            # Center the text for custom fonts
            text_width, text_height = draw.textbbox((0, 0), text, font=font)[2:4]
            position = ((256 - text_width) // 2, (256 - text_height) // 2 - 20)
            
        # Draw the text
        draw.text(position, text, fill=text_color, font=font)
            
    except Exception as e:
        # If there's an error with the font, create a simpler fallback
        logger.error(f"Error using font: {e}. Using simple background.")
        # Just draw a filled circle in the center
        draw.ellipse([(64, 64), (192, 192)], fill=text_color)
    
    # Save as PNG (for apple-touch-icon)
    png_path = os.path.join(output_directory, 'favicon.png')
    img.save(png_path, 'PNG')
    logger.info(f"Created favicon.png at {png_path}")
    
    # Resize and save as ICO
    ico_img = img.resize((32, 32), Image.LANCZOS)
    ico_path = os.path.join(output_directory, 'favicon.ico')
    ico_img.save(ico_path, 'ICO')
    logger.info(f"Created favicon.ico at {ico_path}")
    
    # Create apple-touch-icon specific files
    apple_icon = img.resize((180, 180), Image.LANCZOS)
    apple_paths = [
        os.path.join(output_directory, 'apple-touch-icon.png'),
        os.path.join(output_directory, 'apple-touch-icon-precomposed.png')
    ]
    
    for path in apple_paths:
        apple_icon.save(path, 'PNG')
        logger.info(f"Created {os.path.basename(path)} at {path}")
    
    return {
        'favicon.ico': ico_path,
        'favicon.png': png_path,
        'apple-touch-icon.png': apple_paths[0],
        'apple-touch-icon-precomposed.png': apple_paths[1]
    }

if __name__ == "__main__":
    # Configure basic logging
    logging.basicConfig(level=logging.INFO)
    paths = create_simple_favicon()
    print(f"Created favicons at: {paths}")
