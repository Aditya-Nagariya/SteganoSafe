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
logger = logging.getLogger("DB_FIX")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def fix_database():
    """Fix database schema issues"""
    # Get data directory
    app_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(app_dir, 'data')
    db_path = os.path.join(data_dir, 'app.db')
    
    if not os.path.exists(db_path):
        logger.error(f"Database file not found at: {db_path}")
        return False
    
    logger.info(f"Checking database at: {db_path}")
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if activity_logs table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='activity_logs';")
        if not cursor.fetchone():
            logger.info("activity_logs table doesn't exist, no fixes needed")
            conn.close()
            return True
            
        # Get column names for activity_logs table
        cursor.execute('PRAGMA table_info(activity_logs)')
        columns = [column[1] for column in cursor.fetchall()]
        logger.info(f"Current activity_logs columns: {columns}")
        
        # Check if we need to add created_at column
        if 'created_at' not in columns and 'timestamp' not in columns:
            logger.info("Adding timestamp column to activity_logs table")
            cursor.execute('ALTER TABLE activity_logs ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP;')
            conn.commit()
            logger.info("Added timestamp column")
            
        # Check if we need to rename created_at to timestamp
        if 'created_at' in columns and 'timestamp' not in columns:
            logger.info("Need to rename created_at to timestamp")
            
            # SQLite doesn't support direct column renaming, so we need a workaround
            # Create a backup of the old table
            cursor.execute("CREATE TABLE activity_logs_backup AS SELECT * FROM activity_logs;")
            
            # Drop the old table
            cursor.execute("DROP TABLE activity_logs;")
            
            # Create a new table with the correct schema
            cursor.execute("""
            CREATE TABLE activity_logs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                action VARCHAR(255) NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(50),
                user_agent VARCHAR(255),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """)
            
            # Copy the data from the backup, renaming the column
            cursor.execute("""
            INSERT INTO activity_logs (id, user_id, action, timestamp, ip_address, user_agent)
            SELECT id, user_id, action, created_at, ip_address, user_agent FROM activity_logs_backup;
            """)
            
            # Drop the backup table
            cursor.execute("DROP TABLE activity_logs_backup;")
            
            conn.commit()
            logger.info("Successfully renamed created_at to timestamp")
        
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error fixing database: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    success = fix_database()
    if success:
        logger.info("Database fix completed successfully")
        sys.exit(0)
    else:
        logger.error("Database fix failed")
        sys.exit(1)
