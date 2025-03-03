#!/usr/bin/env python3
import os
import sys
import logging
import time
import subprocess
import pathlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("DB_INIT")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_db_migration():
    """Run the database migration script as a separate process"""
    logger.info("Running database migration...")
    
    try:
        # Run db_migrate.py as a separate process
        result = subprocess.run(
            [sys.executable, 'db_migrate.py'],
            capture_output=True,
            text=True,
            check=True
        )
        
        logger.info("Migration script output:")
        for line in result.stdout.splitlines():
            logger.info(f"  {line}")
            
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Migration script failed with exit code {e.returncode}")
        logger.error(f"Migration script stderr: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Error running migration script: {str(e)}")
        return False

def check_database():
    """Run the database check script"""
    logger.info("Checking database state...")
    
    try:
        # Run db_check.py as a separate process
        result = subprocess.run(
            [sys.executable, 'db_check.py'],
            capture_output=True,
            text=True,
            check=True
        )
        
        logger.info("Database check output:")
        for line in result.stdout.splitlines():
            logger.info(f"  {line}")
            
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Database check script failed with exit code {e.returncode}")
        logger.error(f"Database check stderr: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Error running database check: {str(e)}")
        return False

def init_database():
    """Initialize the database for the application"""
    logger.info("Starting database initialization...")
    
    # Ensure data directory exists
    app_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(app_dir, 'data')
    os.makedirs(data_dir, exist_ok=True)
    os.chmod(data_dir, 0o777)  # Full permissions
    logger.info(f"Data directory: {data_dir}")
    
    # Run migrations
    if not run_db_migration():
        logger.error("Database migration failed!")
        return False
        
    # Check database status
    if not check_database():
        logger.error("Database check failed!")
        return False
    
    logger.info("Database initialization completed successfully!")
    return True

if __name__ == "__main__":
    success = False
    max_retries = 3
    
    for attempt in range(max_retries):
        logger.info(f"Database initialization attempt {attempt + 1} of {max_retries}")
        
        if init_database():
            success = True
            break
        
        if attempt < max_retries - 1:
            wait_time = 2 * (attempt + 1)
            logger.info(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
    
    if not success:
        logger.critical("Database initialization FAILED after multiple attempts!")
        sys.exit(1)
    else:
        logger.info("Database initialization SUCCEEDED!")
