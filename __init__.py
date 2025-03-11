"""
SteganoSafe application package
"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Import modules after creating app to avoid circular imports
def create_app():
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('config.Config')
    
    # Initialize extensions and register blueprints
    from .models import db
    db.init_app(app)
    
    # Register blueprints
    from .routes import routes_bp
    app.register_blueprint(routes_bp)
    
    # Configure logging
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    return app
