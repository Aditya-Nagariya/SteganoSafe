#!/usr/bin/env python3
"""
Admin debugging utility for SteganoSafe.
Helps diagnose issues with the admin panel and displays useful information.
"""
import os
import sys
import logging
from flask import Flask
import json
import sqlite3
import traceback
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add the current directory to the path for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Try to import our models
try:
    from models import db, User, StegoImage, ActivityLog
    from config import Config
    has_models = True
except ImportError:
    logger.warning("Could not import models - will try direct database access")
    has_models = False

def create_app():
    """Create a minimal Flask app for debugging"""
    app = Flask(__name__)
    app.config.from_object(Config)
    if has_models:
        db.init_app(app)
    return app

def check_database():
    """Check database connection and schema"""
    logger.info("Checking database...")
    
    # Get database path
    db_path = None
    try:
        if has_models:
            app = create_app()
            with app.app_context():
                db_uri = app.config['SQLALCHEMY_DATABASE_URI']
                if db_uri.startswith('sqlite:///'):
                    db_path = db_uri[10:]
                    if not os.path.isabs(db_path):
                        # Convert relative path to absolute
                        db_path = os.path.join(app.root_path, db_path)
        else:
            # Try to find the database in common locations
            possible_paths = [
                'app.db',
                'data/app.db',
                '../data/app.db'
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    db_path = os.path.abspath(path)
                    break
    except Exception as e:
        logger.error(f"Error finding database: {e}")
        return False
    
    if not db_path or not os.path.exists(db_path):
        logger.error(f"Database file not found at {db_path}")
        return False
    
    logger.info(f"Database found at {db_path}")
    
    # Try to connect to database directly
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        logger.info(f"Found tables: {', '.join(tables)}")
        
        # Check users table
        if 'users' in tables:
            cursor.execute("PRAGMA table_info(users);")
            columns = [row[1] for row in cursor.fetchall()]
            logger.info(f"Users table columns: {', '.join(columns)}")
            
            # Check admin users
            cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin';")
            admin_count = cursor.fetchone()[0]
            logger.info(f"Found {admin_count} admin user(s)")
            
            # List admin users
            if admin_count > 0:
                cursor.execute("SELECT id, username, email FROM users WHERE role='admin';")
                admins = cursor.fetchall()
                for admin in admins:
                    logger.info(f"Admin user: {admin[1]} (ID: {admin[0]}, Email: {admin[2]})")
        
        # Check activity_logs table
        if 'activity_logs' in tables:
            cursor.execute("PRAGMA table_info(activity_logs);")
            columns = [row[1] for row in cursor.fetchall()]
            logger.info(f"Activity logs table columns: {', '.join(columns)}")
            
            # Check if timestamp or created_at column exists
            has_timestamp = 'timestamp' in columns
            has_created_at = 'created_at' in columns
            if has_timestamp:
                logger.info("Table has 'timestamp' column (correct)")
            elif has_created_at:
                logger.warning("Table has 'created_at' column but should be 'timestamp'")
            else:
                logger.error("Activity logs table is missing timestamp/created_at column!")
        
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Database error: {e}")
        logger.error(traceback.format_exc())
        return False

def check_templates():
    """Check admin templates"""
    logger.info("Checking admin templates...")
    
    # Get template directory
    template_dir = os.path.join(os.path.dirname(__file__), 'templates', 'admin')
    if not os.path.exists(template_dir):
        logger.error(f"Admin template directory not found: {template_dir}")
        return False
    
    # Check required templates
    required_templates = [
        'base.html', 
        'index.html', 
        'users.html', 
        'user_detail.html', 
        'activity.html',
        'images.html'
    ]
    
    missing_templates = []
    for template in required_templates:
        template_path = os.path.join(template_dir, template)
        if not os.path.exists(template_path):
            missing_templates.append(template)
            logger.error(f"Missing required template: {template}")
        else:
            logger.info(f"Found template: {template}")
    
    if missing_templates:
        logger.error(f"Missing required templates: {', '.join(missing_templates)}")
        return False
    
    return True

def check_static_files():
    """Check admin static files"""
    logger.info("Checking admin static files...")
    
    # Get static directory
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    if not os.path.exists(static_dir):
        logger.error(f"Static directory not found: {static_dir}")
        return False
    
    # Check admin.css
    admin_css = os.path.join(static_dir, 'css', 'admin.css')
    if not os.path.exists(admin_css):
        logger.error(f"Admin CSS file not found: {admin_css}")
        return False
    else:
        logger.info(f"Found admin.css: {admin_css}")
    
    # Check admin JS files
    admin_js = os.path.join(static_dir, 'js', 'admin_charts.js')
    if not os.path.exists(admin_js):
        logger.warning(f"Admin charts JS file not found: {admin_js}")
    else:
        logger.info(f"Found admin_charts.js: {admin_js}")
    
    return True

def check_routes():
    """Check admin route definitions"""
    logger.info("Checking admin routes...")
    
    # Check if admin_routes.py exists
    routes_file = os.path.join(os.path.dirname(__file__), 'admin_routes.py')
    if not os.path.exists(routes_file):
        logger.error(f"Admin routes file not found: {routes_file}")
        return False
    
    # Check content of routes file
    try:
        with open(routes_file, 'r') as f:
            content = f.read()
            
        # Check for required route definitions
        required_routes = [
            '@admin_bp.route', 
            'def index', 
            'def users',
            'def user_detail',
            'def activity',
            'def images'
        ]
        
        missing_routes = []
        for route in required_routes:
            if route not in content:
                missing_routes.append(route)
                logger.error(f"Missing required route definition: {route}")
            else:
                logger.info(f"Found route definition: {route}")
        
        if missing_routes:
            logger.error(f"Missing required route definitions!")
            return False
            
        # Check for blueprint registration
        app_file = os.path.join(os.path.dirname(__file__), 'app.py')
        if os.path.exists(app_file):
            with open(app_file, 'r') as f:
                app_content = f.read()
                
            if 'app.register_blueprint(admin_bp' in app_content:
                logger.info("Admin blueprint is registered in app.py")
            else:
                logger.error("Admin blueprint is NOT registered in app.py!")
                return False
        else:
            logger.warning("Could not find app.py to check blueprint registration")
            
        return True
    except Exception as e:
        logger.error(f"Error checking routes: {e}")
        return False

def main():
    """Main function to run all checks"""
    print("\n" + "=" * 60)
    print(" SteganoSafe Admin Debug Utility ")
    print("=" * 60)
    
    success = True
    
    # Run all checks
    if not check_database():
        success = False
        
    if not check_templates():
        success = False
        
    if not check_static_files():
        success = False
        
    if not check_routes():
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print(" ✓ All admin checks passed! Admin panel should work correctly")
    else:
        print(" ✗ Some checks failed! See log for details")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
