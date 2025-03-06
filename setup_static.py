#!/usr/bin/env python3
"""
Set up the static directory structure for the application
"""
import os
import shutil
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("setup_static")

def setup_static_directories():
    """Set up the static directory structure"""
    # Get the base directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define the directories to create
    directories = [
        'static',
        'static/css',
        'static/js',
        'static/img',
        'static/uploads'
    ]
    
    # Create each directory if it doesn't exist
    for directory in directories:
        dir_path = os.path.join(base_dir, directory)
        if not os.path.exists(dir_path):
            logger.info(f"Creating directory: {directory}")
            os.makedirs(dir_path)
        else:
            logger.info(f"Directory already exists: {directory}")
    
    # Run favicon generation
    try:
        logger.info("Generating favicon...")
        from create_favicon import create_simple_favicon
        create_simple_favicon()
        logger.info("Favicon generated successfully")
    except Exception as e:
        logger.error(f"Error generating favicon: {e}")

if __name__ == "__main__":
    setup_static_directories()
