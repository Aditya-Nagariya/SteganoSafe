"""
Script to ensure the database exists and is in a persistent location
"""
import os
import logging
import sys
import platform
import sqlite3

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def get_persistent_data_dir():
    """
    Get a platform-appropriate persistent data directory that will survive restarts
    """
    # For cloud platforms like Render.com, use specific persistent directories
    if os.environ.get('RENDER'):
        # Render.com - use the persistent disk path
        base_dir = '/data'
        if not os.path.exists(base_dir):
            # Try to create it if it doesn't exist
            try:
                os.makedirs(base_dir, exist_ok=True)
                logger.info(f"Created persistent directory at {base_dir}")
            except Exception as e:
                logger.error(f"Failed to create persistent directory: {e}")
                # Fall back to a directory that should work
                base_dir = os.path.join(os.getcwd(), 'persistent_data')
                os.makedirs(base_dir, exist_ok=True)
    else:
        # Local development - use a directory in the project
        base_dir = os.path.join(os.getcwd(), 'persistent_data')
        os.makedirs(base_dir, exist_ok=True)
    
    logger.info(f"Using persistent data directory: {base_dir}")
    return base_dir

def ensure_database():
    """
    Ensure database exists and is in a persistent location
    Returns (data_dir, database_path)
    """
    # Get persistent data directory
    data_dir = get_persistent_data_dir()
    
    # Create database directory if it doesn't exist
    db_dir = os.path.join(data_dir, 'db')
    os.makedirs(db_dir, exist_ok=True)
    
    # Set up database path
    db_path = os.path.join(db_dir, 'steganosafe.sqlite')
    
    # Log the database path for debugging
    logger.info(f"Database path: {db_path}")
    
    # Test that we can create/access the database
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS db_test (id INTEGER PRIMARY KEY, test TEXT)')
        cursor.execute('INSERT INTO db_test (test) VALUES (?)', ('Database initialization test',))
        conn.commit()
        cursor.execute('SELECT * FROM db_test')
        result = cursor.fetchone()
        logger.info(f"Database test result: {result}")
        conn.close()
        
        # Ensure the database file exists and is writable
        assert os.path.exists(db_path), "Database file doesn't exist after creation"
        assert os.access(db_path, os.W_OK), "Database file isn't writable"
        
        logger.info(f"Database successfully verified at {db_path}")
        
        # Set environment variable for database path
        os.environ['DATABASE_PATH'] = db_path
        
        return data_dir, db_path
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

if __name__ == "__main__":
    data_dir, db_path = ensure_database()
    print(f"Database ensured at: {db_path}")
    print(f"Data directory: {data_dir}")
