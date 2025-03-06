#!/usr/bin/env python3
"""
Simple script to run the favicon generator
"""
import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the create_favicon function
from create_favicon import create_simple_favicon

if __name__ == "__main__":
    # Ensure we're in the correct directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Create the favicon
    print("Creating favicon files...")
    create_simple_favicon()
    print("Done. Favicon files created in static/img/ directory.")
