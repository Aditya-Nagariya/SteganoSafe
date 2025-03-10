"""
Utility script to diagnose and fix session issues
"""
import os
import sys
import logging
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add the parent directory to the path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

def check_session_directory():
    """Check if session directory exists and is writable"""
    from flask import session
    
    # Get session directory
    session_dir = os.path.join(parent_dir, 'flask_session')
    
    # Check if directory exists
    if not os.path.exists(session_dir):
        logger.info(f"Creating session directory: {session_dir}")
        try:
            os.makedirs(session_dir, exist_ok=True)
            logger.info("Session directory created successfully")
        except Exception as e:
            logger.error(f"Failed to create session directory: {e}")
            return False
    
    # Check if directory is writable
    if not os.access(session_dir, os.W_OK):
        logger.error(f"Session directory is not writable: {session_dir}")
        return False
    
    logger.info(f"Session directory is valid and writable: {session_dir}")
    return True

def check_database_connection():
    """Check database connection"""
    try:
        from steganography_app import db
        from sqlalchemy import text
        
        # Test connection
        result = db.session.execute(text('SELECT 1')).scalar()
        
        if result == 1:
            logger.info("Database connection is working")
            return True
        else:
            logger.error("Database connection test failed")
            return False
    except Exception as e:
        logger.error(f"Error connecting to database: {e}")
        return False

def check_user_persistence():
    """Check if users are persisting in the database"""
    try:
        from steganography_app import db
        from models import User
        
        # Count users
        user_count = User.query.count()
        logger.info(f"Found {user_count} users in the database")
        
        # List first 5 users
        users = User.query.limit(5).all()
        for user in users:
            logger.info(f"User: {user.username}, ID: {user.id}, Role: {user.role}")
        
        return True
    except Exception as e:
        logger.error(f"Error checking user persistence: {e}")
        return False

def fix_session_config():
    """Apply fixes to session configuration"""
    try:
        from steganography_app import create_app
        app = create_app()
        
        with app.app_context():
            # Show current config
            logger.info("Current session config:")
            for key in sorted(app.config.keys()):
                if 'SESSION' in key or 'COOKIE' in key:
                    logger.info(f"  {key}: {app.config[key]}")
            
            # Apply fixes
            logger.info("Applying session configuration fixes...")
            app.config['SESSION_TYPE'] = 'filesystem'
            app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
            app.config['SESSION_COOKIE_SECURE'] = False  # True in production with HTTPS
            app.config['SESSION_COOKIE_HTTPONLY'] = True
            app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
            app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
            app.config['REMEMBER_COOKIE_REFRESH_EACH_REQUEST'] = True
            
            # Show updated config
            logger.info("Updated session config:")
            for key in sorted(app.config.keys()):
                if 'SESSION' in key or 'COOKIE' in key:
                    logger.info(f"  {key}: {app.config[key]}")
            
            logger.info("Session configuration fixes applied")
            return True
    except Exception as e:
        logger.error(f"Error fixing session config: {e}")
        return False

def run_diagnostics():
    """Run all diagnostic checks and fixes"""
    logger.info("Starting session diagnostics")
    
    check_session_directory()
    check_database_connection()
    check_user_persistence()
    fix_session_config()
    
    logger.info("Session diagnostics complete")

if __name__ == "__main__":
    run_diagnostics()
