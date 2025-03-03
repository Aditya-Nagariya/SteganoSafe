#!/usr/bin/env python3
import os
import sys
import logging
import time
import sqlite3
import pathlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("DB_MIGRATE")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def ensure_data_dir():
    """Ensure data directory exists with proper permissions"""
    app_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(app_dir, 'data')
    
    try:
        # Create data directory with full permissions if it doesn't exist
        os.makedirs(data_dir, exist_ok=True)
        os.chmod(data_dir, 0o777)  # Full permissions
        logger.info(f"Data directory created/verified at {data_dir}")
        
        return data_dir
    except Exception as e:
        logger.error(f"Error creating data directory: {str(e)}")
        raise

def drop_all_tables(db_path):
    """Drop all existing tables from the database"""
    try:
        # Check if database file exists
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get list of all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            # Drop each table
            for table in tables:
                table_name = table[0]
                if table_name != 'sqlite_sequence':  # Skip SQLite internal tables
                    logger.info(f"Dropping table: {table_name}")
                    cursor.execute(f"DROP TABLE IF EXISTS {table_name};")
            
            conn.commit()
            conn.close()
            logger.info("All tables dropped successfully")
    except Exception as e:
        logger.error(f"Error dropping tables: {str(e)}")
        raise

def init_database():
    """Initialize the database with proper tables"""
    try:
        # Ensure data directory exists
        data_dir = ensure_data_dir()
        
        # Set database path
        db_path = os.path.join(data_dir, 'app.db')
        logger.info(f"Database path: {db_path}")
        
        # Check if database file exists and remove it if it does
        if os.path.exists(db_path):
            logger.info(f"Removing existing database: {db_path}")
            os.remove(db_path)
        
        # Import Flask app and database
        from app import app, db
        
        # Import models to ensure they're registered with SQLAlchemy
        from models import User, StegoImage, ActivityLog
        
        # Create database tables
        with app.app_context():
            logger.info("Creating database tables...")
            db.create_all()
            
            # Verify table creation
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            logger.info(f"Created tables: {tables}")
            
            # Check required tables
            required_tables = ['users', 'stego_images', 'activity_logs']
            missing_tables = [table for table in required_tables if table not in tables]
            
            if missing_tables:
                logger.error(f"Missing tables: {missing_tables}")
                raise Exception(f"Failed to create tables: {missing_tables}")
            
            # Create default admin user
            admin_username = app.config.get('DEFAULT_ADMIN_USERNAME', 'admin')
            admin_exists = User.query.filter_by(username=admin_username).first()
            
            if not admin_exists:
                logger.info(f"Creating default admin user: {admin_username}")
                
                admin = User(
                    username=admin_username,
                    email=app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com'),
                    phone_number=app.config.get('DEFAULT_ADMIN_PHONE', '+1234567890'),
                    is_verified=True,
                    role='admin'
                )
                admin.set_password(app.config.get('DEFAULT_ADMIN_PASSWORD', 'admin123'))
                
                db.session.add(admin)
                db.session.commit()
                logger.info("Default admin user created")
            else:
                logger.info("Admin user already exists")
                
        logger.info("Database initialization completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Error during database initialization: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    logger.info("Starting database migration...")
    success = False
    
    # Try initialization with retries
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"Attempt {attempt + 1} of {max_retries}...")
            if init_database():
                success = True
                break
            else:
                logger.error(f"Initialization failed on attempt {attempt + 1}")
                time.sleep(2)  # Wait before retry
        except Exception as e:
            logger.error(f"Exception during attempt {attempt + 1}: {str(e)}")
            time.sleep(2)  # Wait before retry
    
    if not success:
        logger.critical("Database migration FAILED after multiple attempts!")
        sys.exit(1)
    else:
        logger.info("Database migration completed successfully!")
