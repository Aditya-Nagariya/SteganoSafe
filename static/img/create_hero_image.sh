#!/bin/bash

# This is a script to generate a placeholder hero image if you don't have one
# It requires ImageMagick to be installed

# Create the directory if it doesn't exist
mkdir -p "$(dirname "$0")"

# Create a stylized placeholder hero image
convert -size 800x600 gradient:'#4361ee-#3a0ca3' \
    -fill white -pointsize 30 -gravity center \
    -draw "text 0,0 'SteganoSafe'" \
    -draw "text 0,50 'Secure Steganography'" \
    -fill rgba\(255,255,255,0.2\) \
    -draw "circle 200,300 200,350" \
    -draw "circle 600,300 600,380" \
    "$(dirname "$0")/hero-image.png"

echo "Hero image created at $(dirname "$0")/hero-image.png"

# Note: You should replace this placeholder with a real hero image
# showing steganography concept, like a hidden message in an image
