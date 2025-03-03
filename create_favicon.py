#!/usr/bin/env python
import os
from PIL import Image, ImageDraw

def create_favicon():
    """Creates a simple favicon for the application"""
    
    img_dir = os.path.join('static')
    os.makedirs(img_dir, exist_ok=True)
    
    # Create a 32x32 image with transparent background
    favicon = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(favicon)
    
    # Draw a shield shape as background
    draw.polygon(
        [(16, 2), (30, 10), (30, 20), (16, 30), (2, 20), (2, 10)],
        fill=(67, 97, 238, 255)  # Primary color #4361ee
    )
    
    # Draw a lock shape in the center
    # Lock body
    draw.rectangle(
        [(12, 14), (20, 24)],
        fill=(255, 255, 255, 230)
    )
    
    # Lock shackle
    draw.arc(
        [(11, 11), (21, 20)], 
        180, 0,
        fill=(255, 255, 255, 230),
        width=2
    )
    
    # Save in various sizes
    favicon.save(os.path.join(img_dir, 'favicon.png'))
    
    # Convert to ICO format
    try:
        favicon.save(os.path.join(img_dir, 'favicon.ico'))
        print(f"Favicon created at {os.path.join(img_dir, 'favicon.ico')}")
    except Exception as e:
        print(f"Could not create ICO file: {e}")
        print(f"PNG favicon created at {os.path.join(img_dir, 'favicon.png')}")

if __name__ == "__main__":
    create_favicon()
