#!/usr/bin/env python3
import os
import sys
import logging
import sqlite3
import pathlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("DB_CHECK")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_database():
    """Check the database status and print diagnostic information"""
    logger.info("Checking database status...")
    
    # Get application directory
    app_dir = os.path.dirname(os.path.abspath(__file__))
    logger.info(f"App directory: {app_dir}")
    
    # Check data directory
    data_dir = os.path.join(app_dir, 'data')
    if os.path.exists(data_dir):
        logger.info(f"Data directory exists: {data_dir}")
        logger.info(f"Data directory permissions: {oct(os.stat(data_dir).st_mode)[-3:]}")
        
        # List files in data directory
        files = os.listdir(data_dir)
        logger.info(f"Files in data directory: {files}")
    else:
        logger.error(f"Data directory does not exist: {data_dir}")
    
    # Check for database file
    db_path = os.path.join(data_dir, 'app.db')
    if os.path.exists(db_path):
        logger.info(f"Database file exists: {db_path}")
        logger.info(f"Database file size: {os.path.getsize(db_path)} bytes")
        logger.info(f"Database file permissions: {oct(os.stat(db_path).st_mode)[-3:]}")
        
        # Check database structure
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get list of all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            logger.info(f"Database tables: {[table[0] for table in tables]}")
            
            # Check users table
            if any(table[0] == 'users' for table in tables):
                # Count users
                cursor.execute("SELECT COUNT(*) FROM users;")
                user_count = cursor.fetchone()[0]
                logger.info(f"Number of users: {user_count}")
                
                # Get admin user
                cursor.execute("SELECT id, username, email FROM users WHERE role='admin';")
                admin = cursor.fetchone()
                if admin:
                    logger.info(f"Admin user found: id={admin[0]}, username={admin[1]}")
                else:
                    logger.warning("No admin user found")
            else:
                logger.error("Users table does not exist!")
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Error checking database structure: {str(e)}")
    else:
        logger.error(f"Database file does not exist: {db_path}")
    
    # Check SQLAlchemy connection
    try:
        from app import app, db
        
        with app.app_context():
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            logger.info(f"SQLAlchemy detected tables: {tables}")
            
            from models import User
            admin_count = User.query.filter_by(role='admin').count()
            logger.info(f"Admin count via SQLAlchemy: {admin_count}")
    except Exception as e:
        logger.error(f"Error checking SQLAlchemy: {str(e)}")

if __name__ == "__main__":
    check_database()
