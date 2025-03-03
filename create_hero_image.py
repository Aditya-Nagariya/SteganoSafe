#!/usr/bin/env python
import os
import sys
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import numpy as np
from io import BytesIO

def create_hero_image():
    """Creates a placeholder hero image with gradients and simple design elements"""
    
    # Create the directory if it doesn't exist
    img_dir = os.path.join('static', 'img')
    os.makedirs(img_dir, exist_ok=True)
    
    # Set dimensions
    width = 1200
    height = 600
    
    # Create a gradient background
    gradient = Image.new('RGB', (width, height), color='#4361ee')
    draw = ImageDraw.Draw(gradient)
    
    # Draw gradient manually by creating horizontal lines with color transition
    for y in range(height):
        # Calculate color gradient from primary to secondary color
        r = int(67 - (67 - 58) * (y / height))  # 4361ee to 3a0ca3
        g = int(97 - (97 - 12) * (y / height))
        b = int(238 - (238 - 163) * (y / height))
        
        draw.line([(0, y), (width, y)], fill=(r, g, b))
    
    # Apply a slight blur for smoother gradient
    gradient = gradient.filter(ImageFilter.GaussianBlur(radius=1))
    
    # Create a new transparent layer for design elements
    overlay = Image.new('RGBA', (width, height), (255, 255, 255, 0))
    draw = ImageDraw.Draw(overlay)
    
    # Draw geometric elements (circles, polygons, etc.)
    # Large circle in the background
    draw.ellipse([(width-400, -100), (width+100, 400)], 
                 fill=(255, 255, 255, 15))
    
    # Small circles
    for i in range(10):
        x = np.random.randint(0, width)
        y = np.random.randint(0, height)
        size = np.random.randint(10, 50)
        opacity = np.random.randint(10, 30)
        draw.ellipse([(x, y), (x+size, y+size)], 
                     fill=(255, 255, 255, opacity))
    
    # Create a mockup of hidden message in an image
    # Image frame
    frame_width = 400
    frame_height = 300
    frame_x = width - frame_width - 100
    frame_y = height // 2 - frame_height // 2
    
    # Draw image frame with shadow
    shadow_offset = 15
    draw.rectangle(
        [(frame_x + shadow_offset, frame_y + shadow_offset), 
         (frame_x + frame_width + shadow_offset, frame_y + frame_height + shadow_offset)],
        fill=(0, 0, 0, 50)
    )
    
    # Draw image frame
    draw.rectangle(
        [(frame_x, frame_y), (frame_x + frame_width, frame_y + frame_height)],
        fill=(255, 255, 255, 230),
        outline=(255, 255, 255, 255),
        width=2
    )
    
    # Add lock icon to represent security
    lock_size = 60
    lock_x = width // 4
    lock_y = height // 2 - lock_size
    
    # Lock body
    draw.rectangle(
        [(lock_x, lock_y + lock_size//3), 
         (lock_x + lock_size, lock_y + lock_size)],
        fill=(255, 255, 255, 200),
        outline=(255, 255, 255, 255),
        width=2
    )
    
    # Lock shackle
    draw.arc(
        [(lock_x + lock_size//4, lock_y - lock_size//6), 
         (lock_x + lock_size - lock_size//4, lock_y + lock_size//2)],
        0, 180,
        fill=(255, 255, 255, 230),
        width=4
    )
    
    # Add binary data visualization to represent hidden data
    binary_start_x = 150
    binary_start_y = height // 2 + 50
    binary_width = 300
    binary_height = 100
    
    for i in range(60):
        x = binary_start_x + (i % 20) * 15
        y = binary_start_y + (i // 20) * 20
        bit = np.random.choice([0, 1])
        color = (255, 255, 255, 200) if bit else (255, 255, 255, 100)
        draw.text((x, y), str(bit), fill=color, font=None)
    
    # Try to load a font, use default if not available
    try:
        font_path = os.path.join('static', 'fonts', 'Poppins-Bold.ttf')
        if os.path.exists(font_path):
            title_font = ImageFont.truetype(font_path, 60)
            subtitle_font = ImageFont.truetype(font_path, 30)
        else:
            title_font = ImageFont.load_default()
            subtitle_font = ImageFont.load_default()
            
    except Exception:
        title_font = ImageFont.load_default()
        subtitle_font = ImageFont.load_default()
    
    # Add title and subtitle
    title = "SteganoSafe"
    subtitle = "Secure your messages with steganography"
    
    draw.text(
        (100, height // 4),
        title,
        fill=(255, 255, 255, 230),
        font=title_font
    )
    
    draw.text(
        (100, height // 4 + 80),
        subtitle,
        fill=(255, 255, 255, 180),
        font=subtitle_font
    )
    
    # Composite the overlay onto the gradient background
    result = Image.alpha_composite(gradient.convert('RGBA'), overlay)
    
    # Save the image
    output_path = os.path.join(img_dir, 'hero-image.png')
    result.convert('RGB').save(output_path)
    
    print(f"Hero image created at {output_path}")
    return output_path

if __name__ == "__main__":
    create_hero_image()
