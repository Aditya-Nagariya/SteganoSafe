"""
Utility to ensure database exists and is initialized properly
"""
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def ensure_database():
    """Ensure database directory exists and return paths"""
    try:
        # Base directory
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Data directory
        data_dir = os.path.join(base_dir, 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Database path
        db_path = os.path.join(data_dir, 'steganography_app.db')
        
        # Touch the file if it doesn't exist
        if not os.path.exists(db_path):
            Path(db_path).touch()
            logger.info(f"Created empty database file: {db_path}")
        
        # Fix permissions
        try:
            os.chmod(data_dir, 0o777)
            os.chmod(db_path, 0o666)
            logger.info("Set permissions on data directory and database file")
        except Exception as e:
            logger.warning(f"Could not set permissions: {e}")
        
        return data_dir, db_path
    except Exception as e:
        logger.error(f"Error ensuring database: {e}")
        raise

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    data_dir, db_path = ensure_database()
    print(f"Database ensured at: {db_path}")
    print(f"Data directory: {data_dir}")
