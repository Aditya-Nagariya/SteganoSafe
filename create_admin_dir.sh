#!/bin/bash

# Create necessary template directories
mkdir -p "/Users/aditya/Desktop/untitled folder/steganography_app/templates/admin"
mkdir -p "/Users/aditya/Desktop/untitled folder/steganography_app/templates/errors"

# Print success message
echo "Created directory structure for templates"
echo "- /templates/admin/"
echo "- /templates/errors/"

# Make this script executable
chmod +x "$0"

# Instructions
echo ""
echo "Run this script with: bash create_admin_dir.sh"
