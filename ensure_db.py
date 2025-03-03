import os
import sys
import logging
import pathlib
import sqlite3
from contextlib import suppress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("DB_ENSURE")

def ensure_database():
    """Ensure database exists and is accessible at runtime"""
    try:
        # Get app directory and ensure data directory exists
        app_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(app_dir, 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Set full permissions to ensure app can write to it
        with suppress(Exception):
            os.chmod(data_dir, 0o777)
            
        logger.info(f"Data directory ensured at: {data_dir}")
        
        # Create db file path
        db_path = os.path.join(data_dir, 'app.db')
        logger.info(f"Database path: {db_path}")
        
        # Try to connect to database to verify it works
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Basic query to check if the database connection works
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        logger.info(f"Existing tables: {[table[0] for table in tables]}")
        
        # Check if required tables exist, if not, we'll create them through the app
        required_tables = ['users', 'stego_images', 'activity_logs']
        missing_tables = [table for table in required_tables if table not in [t[0] for t in tables]]
        
        if missing_tables:
            logger.warning(f"Missing tables will be created by app: {missing_tables}")
        else:
            logger.info("All required tables exist")
            
            # Check users table
            if 'users' in [t[0] for t in tables]:
                # Count users
                cursor.execute("SELECT COUNT(*) FROM users;")
                user_count = cursor.fetchone()[0]
                logger.info(f"Number of users: {user_count}")
        
        conn.close()
        return data_dir, db_path
        
    except Exception as e:
        logger.error(f"Database check error: {str(e)}")
        # Return default paths even if check fails
        app_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(app_dir, 'data')
        db_path = os.path.join(data_dir, 'app.db')
        return data_dir, db_path

# Run when imported to immediately ensure database
data_dir, db_path = ensure_database()
