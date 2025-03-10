"""
WSGI entry point for the SteganoSafe application.
This file is used for deployment on servers like Render, Heroku, etc.
"""
import os
import sys
import logging
from datetime import timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WSGI")

# Important: Add the parent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    # Import after setting up paths
    from steganography_app import create_app
    
    # Create the Flask application
    logger.info("Initializing application...")
    app = create_app()
    
    # Configure session persistence
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
    app.config['REMEMBER_COOKIE_REFRESH_EACH_REQUEST'] = True
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    
    # Configure SQLAlchemy pooling to handle restarts and reconnects
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 280  # Recycle connections before DB timeout
    app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20  # Wait 20s for connection
    app.config['SQLALCHEMY_POOL_SIZE'] = 10  # Max 10 connections in pool
    
    logger.info("Application initialization completed successfully")
except Exception as e:
    logger.error(f"Error initializing application: {str(e)}", exc_info=True)
    raise

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting server on port {port}")
    app.run(host="0.0.0.0", port=port)
