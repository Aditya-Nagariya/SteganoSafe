"""
SteganoSafe application package.
"""
import os
import sys
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Add the application directory to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Now imports should work correctly
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Initialize extensions but don't configure them yet
db = SQLAlchemy()
login_manager = LoginManager()

def create_app(config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    logger.info("Creating Flask application...")
    
    # Load configuration
    if config:
        app.config.from_object(config)
    else:
        app.config.from_pyfile('config.py', silent=True)
    
    # Configure extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'  # May need to update based on your auth routes
    
    try:
        # Import and register routes
        with app.app_context():
            from routes import register_all_routes
            register_all_routes(app)
            logger.info("Routes registered successfully")
    except Exception as e:
        logger.error(f"Error registering routes: {str(e)}", exc_info=True)
        raise
    
    return app
