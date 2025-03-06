#!/usr/bin/env python3
"""
Script to set up the analytics dashboard for SteganoSafe application.
This creates necessary files, directories, and configures the database for analytics.
"""
import os
import sys
import logging
import shutil
import subprocess
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('analytics_setup.log')
    ]
)
logger = logging.getLogger("ANALYTICS_SETUP")

# Constants
STATIC_JS_DIR = os.path.join('static', 'js')
STATIC_CSS_DIR = os.path.join('static', 'css')
TEMPLATES_ADMIN_DIR = os.path.join('templates', 'admin')

def ensure_directories():
    """Ensure necessary directories exist"""
    dirs = [STATIC_JS_DIR, STATIC_CSS_DIR, TEMPLATES_ADMIN_DIR]
    for directory in dirs:
        if not os.path.exists(directory):
            logger.info(f"Creating directory: {directory}")
            os.makedirs(directory, exist_ok=True)

def check_dependencies():
    """Check if required Python packages are installed"""
    required_packages = [
        'pandas',
        'numpy',
        'flask',
        'flask_sqlalchemy',
        'sqlalchemy',
        'plotly',
        'psutil'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.warning(f"Missing required packages: {', '.join(missing_packages)}")
        
        # Prompt to install
        proceed = input(f"Would you like to install missing packages: {', '.join(missing_packages)}? (y/n): ")
        if proceed.lower() == 'y':
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", *missing_packages
                ])
                logger.info("Successfully installed missing packages")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install packages: {e}")
                return False
        else:
            logger.warning("Analytics dashboard may not work correctly without all required packages")
    
    return True

def update_database_schema():
    """Update database schema for analytics support"""
    try:
        # Import app and db from the app module
        sys.path.insert(0, os.getcwd())
        from app import app, db
        from migrate_db import fix_timestamp_columns
        
        # Check if migrations needed
        with app.app_context():
            # Try to add missing columns
            logger.info("Checking database schema for analytics compatibility...")
            fix_timestamp_columns()
            logger.info("Database schema updated successfully")
            
        return True
    except Exception as e:
        logger.error(f"Failed to update database schema: {e}")
        return False

def create_dummy_analytics_data():
    """Create some dummy analytics data for testing"""
    try:
        # Import needed modules
        sys.path.insert(0, os.getcwd())
        from app import app, db
        from models import User, ActivityLog, StegoImage
        from datetime import datetime, timedelta
        import random
        
        # Generate analytics data
        with app.app_context():
            # Check if we already have sufficient test data
            if ActivityLog.query.count() >= 100:
                logger.info("Sufficient activity logs already exist")
                return True
                
            # Get list of users
            users = User.query.all()
            if not users:
                logger.warning("No users found - cannot generate activity logs")
                return False
            
            # Generate activity logs for the past 30 days
            now = datetime.now()
            
            count = 0
            for day in range(30):
                # How many activities on this day
                day_count = random.randint(5, 20)
                day_date = now - timedelta(days=30-day)
                
                for _ in range(day_count):
                    # Random user
                    user = random.choice(users)
                    
                    # Random timestamp within this day
                    timestamp = day_date.replace(
                        hour=random.randint(0, 23),
                        minute=random.randint(0, 59),
                        second=random.randint(0, 59)
                    )
                    
                    # Random action type
                    action_type = random.choice(['login', 'image', 'dashboard', 'decrypt', 'encrypt'])
                    
                    if action_type == 'login':
                        action_text = "User logged in"
                    elif action_type == 'image':
                        action_text = "Viewed image gallery"
                    elif action_type == 'dashboard':
                        action_text = "Viewed dashboard"
                    elif action_type == 'decrypt':
                        action_text = "decrypted image: test-image-123.png"
                    elif action_type == 'encrypt':
                        action_text = "Encrypted image: test-image-123.png"
                        
                    # Create activity log
                    log = ActivityLog(
                        user_id=user.id,
                        action=action_text,
                        timestamp=timestamp,
                        ip_address=f"192.168.1.{random.randint(1, 255)}"
                    )
                    db.session.add(log)
                    count += 1
                    
            db.session.commit()
            logger.info(f"Generated {count} test activity logs")
            
        return True
    except Exception as e:
        logger.error(f"Failed to generate test analytics data: {e}")
        return False

def main():
    """Main function to set up analytics dashboard"""
    print("Setting up SteganoSafe Analytics Dashboard")
    print("-----------------------------------------")
    
    # Ensure required directories
    ensure_directories()
    
    # Check Python package dependencies
    if not check_dependencies():
        print("Warning: Not all dependencies are installed. Dashboard may not function correctly.")
    
    # Update database schema
    if not update_database_schema():
        print("Error: Failed to update database schema. See log for details.")
        return 1
    
    # Create test data
    create_dummy = input("Would you like to generate test data for the analytics dashboard? (y/n): ")
    if create_dummy.lower() == 'y':
        if not create_dummy_analytics_data():
            print("Warning: Failed to create test data. Dashboard may show empty charts.")
    
    # Complete
    print("\nAnalytics dashboard setup complete!")
    print("Please restart your Flask application.")
    print("Access the analytics dashboard at: /admin/analytics")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
