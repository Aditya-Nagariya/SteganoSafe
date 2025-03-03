#!/bin/bash

# Create directory structure
mkdir -p /Users/aditya/Desktop/untitled\ folder/steganography_app/templates/admin
mkdir -p /Users/aditya/Desktop/untitled\ folder/steganography_app/templates/errors
mkdir -p /Users/aditya/Desktop/untitled\ folder/steganography_app/static/js
mkdir -p /Users/aditya/Desktop/untitled\ folder/steganography_app/static/css
mkdir -p /Users/aditya/Desktop/untitled\ folder/steganography_app/static/uploads
mkdir -p /Users/aditya/Desktop/untitled\ folder/steganography_app/uploads

# Make sure uploads is writable
chmod 777 /Users/aditya/Desktop/untitled\ folder/steganography_app/uploads
chmod 777 /Users/aditya/Desktop/untitled\ folder/steganography_app/static/uploads

echo "Directory structure created successfully!"
