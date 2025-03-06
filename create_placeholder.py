from PIL import Image, ImageDraw
import os

def create_placeholder_image():
    """Create a simple placeholder image for missing images"""
    # Create output directory if it doesn't exist
    output_dir = os.path.join(os.path.dirname(__file__), 'static', 'img')
    os.makedirs(output_dir, exist_ok=True)
    
    # Create a simple gray image with a question mark
    img = Image.new('RGB', (80, 80), color=(233, 236, 239))
    draw = ImageDraw.Draw(img)
    
    # Draw a border
    draw.rectangle([(0, 0), (79, 79)], outline=(206, 212, 218), width=2)
    
    # Draw a question mark or icon
    draw.text((30, 20), "?", fill=(108, 117, 125), font=None, font_size=40)
    
    # Save the image
    output_path = os.path.join(output_dir, 'placeholder.png')
    img.save(output_path, 'PNG')
    print(f"Created placeholder image at: {output_path}")
    
    return output_path

if __name__ == "__main__":
    create_placeholder_image()
