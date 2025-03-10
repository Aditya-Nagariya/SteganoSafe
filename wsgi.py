"""
WSGI entry point for the SteganoSafe application.
This file is used for deployment on servers like Render, Heroku, etc.
"""
import os
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WSGI")

# Important: Add the parent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import after setting up paths
from steganography_app import create_app

try:
    # Create the Flask application
    logger.info("Initializing application...")
    app = create_app()
    logger.info("Application initialization completed successfully")
except Exception as e:
    logger.error(f"Error initializing application: {str(e)}", exc_info=True)
    raise

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting server on port {port}")
    app.run(host="0.0.0.0", port=port)
