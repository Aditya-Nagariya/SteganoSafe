"""
Routes package for SteganoSafe application.
This module imports and exposes route initialization functions.
"""

# Import all route initialization functions
from .user import init_user_routes

# Function to register all routes with the Flask app
def register_all_routes(app):
    """Register all application routes with the Flask app"""
    # User routes
    init_user_routes(app)
    
    # Add other route initializations here as needed
    # Example: init_admin_routes(app)
