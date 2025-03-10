"""
SteganoSafe application package.
"""
import os
import sys

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
    
    # Load configuration
    if config:
        app.config.from_object(config)
    else:
        app.config.from_pyfile('config.py', silent=True)
    
    # Configure extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    # Import and register routes
    with app.app_context():
        from routes import register_all_routes
        register_all_routes(app)
    
    return app
