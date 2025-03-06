#!/usr/bin/env python3
"""
Database migration utility for SteganoSafe application.
This script helps migrate data between different schema versions and fix database issues.
"""
import os
import sys
import logging
import sqlite3
import json
import datetime
import shutil
from contextlib import closing

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('db_migration.log')
    ]
)
logger = logging.getLogger("DB_MIGRATE")

# Path to the database
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'app.db')

def backup_database():
    """Create a backup of the database before making changes"""
    if not os.path.exists(DB_PATH):
        logger.error(f"Database file not found: {DB_PATH}")
        return False
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{DB_PATH}.{timestamp}.bak"
    
    try:
        shutil.copy2(DB_PATH, backup_path)
        logger.info(f"Database backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to backup database: {e}")
        return False

def get_schema_info():
    """Get information about the current database schema"""
    if not os.path.exists(DB_PATH):
        logger.error(f"Database file not found: {DB_PATH}")
        return None
    
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row['name'] for row in cursor.fetchall()]
            
            # Get column info for each table
            schema = {}
            for table in tables:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [{'name': row['name'], 'type': row['type']} for row in cursor.fetchall()]
                schema[table] = columns
            
            return schema
    except Exception as e:
        logger.error(f"Error getting schema info: {e}")
        return None

def fix_timestamp_columns():
    """Fix timestamp/created_at columns in the database"""
    logger.info("Checking timestamp columns...")
    
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            cursor = conn.cursor()
            
            # Check activity_logs table
            cursor.execute("PRAGMA table_info(activity_logs)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'timestamp' not in columns and 'created_at' in columns:
                # Need to rename created_at to timestamp
                logger.info("Renaming created_at to timestamp in activity_logs")
                
                # Create a new table with the correct schema
                cursor.execute("""
                CREATE TABLE activity_logs_new (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    action TEXT,
                    timestamp DATETIME,
                    ip_address TEXT,
                    user_agent TEXT
                )
                """)
                
                # Copy data from old table
                cursor.execute("""
                INSERT INTO activity_logs_new (id, user_id, action, timestamp, ip_address, user_agent)
                SELECT id, user_id, action, created_at, ip_address, user_agent FROM activity_logs
                """)
                
                # Replace old table with new one
                cursor.execute("DROP TABLE activity_logs")
                cursor.execute("ALTER TABLE activity_logs_new RENAME TO activity_logs")
                
                conn.commit()
                logger.info("Successfully renamed created_at to timestamp in activity_logs")
            
            # Check stego_images table
            cursor.execute("PRAGMA table_info(stego_images)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'created_at' not in columns:
                # Need to add created_at column
                logger.info("Adding created_at column to stego_images")
                cursor.execute("ALTER TABLE stego_images ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
                conn.commit()
                logger.info("Successfully added created_at column to stego_images")
            
            # Check users table
            cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'created_at' not in columns:
                # Need to add created_at column
                logger.info("Adding created_at column to users")
                cursor.execute("ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
                conn.commit()
                logger.info("Successfully added created_at column to users")
            
            return True
    except Exception as e:
        logger.error(f"Error fixing timestamp columns: {e}")
        return False

def create_missing_tables():
    """Create any missing tables in the database"""
    logger.info("Checking for missing tables...")
    
    try:
        # Import app and db objects to use Flask-SQLAlchemy's table definitions
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from app import app, db
        
        with app.app_context():
            # This will create tables that don't exist yet
            db.create_all()
            logger.info("Created any missing tables")
        
        return True
    except Exception as e:
        logger.error(f"Error creating missing tables: {e}")
        return False

def execute_sql_script(script_path):
    """Execute a SQL script file on the database"""
    if not os.path.exists(script_path):
        logger.error(f"SQL script not found: {script_path}")
        return False
    
    try:
        with open(script_path, 'r') as f:
            sql_script = f.read()
        
        with closing(sqlite3.connect(DB_PATH)) as conn:
            cursor = conn.cursor()
            cursor.executescript(sql_script)
            conn.commit()
        
        logger.info(f"Successfully executed SQL script: {script_path}")
        return True
    except Exception as e:
        logger.error(f"Error executing SQL script: {e}")
        return False

def run_diagnostics():
    """Run diagnostics on the database and print results"""
    logger.info("Running database diagnostics...")
    
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check for user table
            cursor.execute("SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone()['count'] == 0:
                logger.error("Critical: 'users' table is missing")
                return False
            
            # Check for admin user
            cursor.execute("SELECT count(*) as count FROM users WHERE role='admin'")
            admin_count = cursor.fetchone()['count']
            if admin_count == 0:
                logger.warning("Warning: No admin users found")
            else:
                logger.info(f"Found {admin_count} admin users")
            
            # Check user counts
            cursor.execute("SELECT count(*) as count FROM users")
            user_count = cursor.fetchone()['count']
            logger.info(f"Total users: {user_count}")
            
            # Check image counts
            cursor.execute("SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='stego_images'")
            if cursor.fetchone()['count'] > 0:
                cursor.execute("SELECT count(*) as count FROM stego_images")
                image_count = cursor.fetchone()['count']
                logger.info(f"Total images: {image_count}")
            
            # Check activity log counts
            cursor.execute("SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='activity_logs'")
            if cursor.fetchone()['count'] > 0:
                cursor.execute("SELECT count(*) as count FROM activity_logs")
                log_count = cursor.fetchone()['count']
                logger.info(f"Total activity logs: {log_count}")
            
        return True
    except Exception as e:
        logger.error(f"Error running diagnostics: {e}")
        return False

def main():
    """Main entry point for the migration utility"""
    print("SteganoSafe Database Migration Utility")
    print("-------------------------------------")
    
    # Check if database exists
    if not os.path.exists(DB_PATH):
        logger.error(f"Database file not found: {DB_PATH}")
        print(f"Error: Database file not found at {DB_PATH}")
        return 1
    
    # Create backup
    backup_path = backup_database()
    if not backup_path:
        print("Error: Failed to create database backup. Aborting.")
        return 1
    
    print(f"Database backed up to: {backup_path}")
    
    # Get schema info
    schema_info = get_schema_info()
    if schema_info:
        print("Current database tables:")
        for table_name, columns in schema_info.items():
            print(f"  - {table_name} ({len(columns)} columns)")
    
    # Ask user if they want to continue
    if input("Continue with migration? (y/n): ").lower() != 'y':
        print("Migration aborted.")
        return 0
    
    # Fix timestamp columns
    if not fix_timestamp_columns():
        if input("Error fixing timestamp columns. Continue anyway? (y/n): ").lower() != 'y':
            print("Migration aborted.")
            return 1
    
    # Create missing tables
    if not create_missing_tables():
        if input("Error creating missing tables. Continue anyway? (y/n): ").lower() != 'y':
            print("Migration aborted.")
            return 1
    
    # Run diagnostics
    if not run_diagnostics():
        print("Warning: Database diagnostics reported issues. Review the log file.")
    
    print("")
    print("Database migration completed.")
    print("Check db_migration.log for details.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
