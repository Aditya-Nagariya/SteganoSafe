"""
WSGI entry point for Gunicorn
"""
import sys
import os

# Add the parent directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the application factory
from steganography_app import create_app

# Create the application instance - THIS is what Gunicorn looks for
app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
