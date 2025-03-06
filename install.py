#!/usr/bin/env python3
"""
Installation and setup script for the SteganoSafe application.
This script initializes the database, creates required directories,
generates sample data, and configures the application.
"""
import os
import sys
import logging
import shutil
from datetime import datetime
import argparse
import subprocess
import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("INSTALLER")

# Constants
STATIC_DIRS = [
    'static',
    'static/css',
    'static/js',
    'static/img',
    'static/uploads',
    'data'
]

REQUIRED_PACKAGES = [
    'flask',
    'flask-sqlalchemy',
    'flask-login',
    'flask-wtf',
    'flask-migrate',
    'werkzeug',
    'pillow',
    'email_validator',
    'cryptography',
    'flask-socketio',
    'flask-mail',
    'flask-cors',
]

def create_directories():
    """Create required directory structure"""
    logger.info("Creating directory structure...")
    
    for directory in STATIC_DIRS:
        dir_path = os.path.join(os.getcwd(), directory)
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path)
                logger.info(f"Created directory: {directory}")
            except Exception as e:
                logger.error(f"Failed to create directory {directory}: {e}")
                return False
        else:
            logger.info(f"Directory already exists: {directory}")
            
    return True

def check_python_version():
    """Check Python version (3.7+ required)"""
    logger.info("Checking Python version...")
    
    version_info = sys.version_info
    if version_info.major < 3 or (version_info.major == 3 and version_info.minor < 7):
        logger.error("Python 3.7 or higher is required")
        return False
    
    logger.info(f"Python version: {platform.python_version()} (OK)")
    return True

def install_packages():
    """Install required Python packages"""
    logger.info("Installing required packages...")
    
    # Check if pip is available
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        logger.error("pip is not available. Please install pip first.")
        return False
    
    # Install packages
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + REQUIRED_PACKAGES
        logger.info(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        logger.info("Packages installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install packages: {e}")
        return False

def setup_database():
    """Initialize and set up the database"""
    logger.info("Setting up database...")
    
    try:
        # Import ensure_db and run it
        sys.path.insert(0, os.getcwd())
        
        try:
            from ensure_db import ensure_database
            data_dir, db_path = ensure_database()
            logger.info(f"Database ensured at: {db_path}")
            
            # Set environment variable
            os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'
            
            # Now create tables and admin user
            from app import app, db, create_default_admin
            with app.app_context():
                db.create_all()
                create_default_admin()
                logger.info("Database tables created and admin user set up")
                
            return True
        except ImportError:
            logger.error("Failed to import ensure_db. Make sure the file exists.")
            return False
    except Exception as e:
        logger.error(f"Database setup error: {e}")
        return False

def generate_favicon():
    """Generate favicon files"""
    logger.info("Generating favicon files...")
    
    try:
        from create_favicon import create_simple_favicon
        create_simple_favicon()
        logger.info("Favicon generated successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to generate favicon: {e}")
        return False

def generate_test_data(num_users=5, num_images=10, num_activities=50):
    """Generate test data for the application"""
    logger.info("Generating test data...")
    
    try:
        from generate_test_data import generate_test_data
        result = generate_test_data(num_users, num_images, num_activities)
        if result:
            logger.info("Test data generated successfully")
        else:
            logger.warning("Test data generation may have had issues")
        return result
    except Exception as e:
        logger.error(f"Failed to generate test data: {e}")
        return False

def create_requirements_file():
    """Create requirements.txt file"""
    logger.info("Creating requirements.txt file...")
    
    try:
        with open('requirements.txt', 'w') as f:
            for package in REQUIRED_PACKAGES:
                f.write(f"{package}\n")
        logger.info("requirements.txt file created")
        return True
    except Exception as e:
        logger.error(f"Failed to create requirements.txt: {e}")
        return False

def create_run_script():
    """Create a shell script to run the application"""
    logger.info("Creating run script...")
    
    try:
        # Determine if we're on Windows or Unix-like system
        if platform.system() == 'Windows':
            script_name = 'run.bat'
            script_content = '@echo off\n' \
                            'echo Starting SteganoSafe application...\n' \
                            'python app.py\n' \
                            'pause\n'
        else:
            script_name = 'run.sh'
            script_content = '#!/bin/bash\n' \
                            'echo "Starting SteganoSafe application..."\n' \
                            'python app.py\n'
        
        with open(script_name, 'w') as f:
            f.write(script_content)
        
        # Make the script executable on Unix-like systems
        if platform.system() != 'Windows':
            os.chmod(script_name, 0o755)
        
        logger.info(f"{script_name} created")
        return True
    except Exception as e:
        logger.error(f"Failed to create run script: {e}")
        return False

def main():
    """Main installation function"""
    parser = argparse.ArgumentParser(description="SteganoSafe Installer")
    parser.add_argument('--no-packages', action='store_true', 
                        help='Skip installing Python packages')
    parser.add_argument('--no-test-data', action='store_true',
                        help='Skip generating test data')
    parser.add_argument('--users', type=int, default=5,
                        help='Number of test users to generate')
    parser.add_argument('--images', type=int, default=10,
                        help='Number of test images to generate')
    parser.add_argument('--activities', type=int, default=50,
                        help='Number of test activities to generate')
    args = parser.parse_args()
    
    logger.info("Starting SteganoSafe installation...")
    logger.info(f"Working directory: {os.getcwd()}")
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Create directory structure
    if not create_directories():
        return 1
    
    # Install required packages
    if not args.no_packages:
        if not install_packages():
            logger.warning("Package installation failed, but continuing with setup")
    else:
        logger.info("Skipping package installation")
    
    # Create requirements file
    if not create_requirements_file():
        logger.warning("Failed to create requirements.txt file, but continuing")
    
    # Generate favicon
    if not generate_favicon():
        logger.warning("Favicon generation failed, but continuing with setup")
    
    # Set up database
    if not setup_database():
        logger.error("Database setup failed. Installation aborted.")
        return 1
    
    # Generate test data
    if not args.no_test_data:
        if not generate_test_data(args.users, args.images, args.activities):
            logger.warning("Test data generation failed, but continuing with setup")
    else:
        logger.info("Skipping test data generation")
    
    # Create run script
    if not create_run_script():
        logger.warning("Run script creation failed, but continuing")
    
    # Installation complete
    logger.info("")
    logger.info("=== INSTALLATION COMPLETE ===")
    logger.info("You can now run the application with:")
    if platform.system() == 'Windows':
        logger.info("    run.bat")
    else:
        logger.info("    ./run.sh")
    logger.info("")
    logger.info("Default admin login:")
    logger.info("    Username: admin")
    logger.info("    Password: admin123")
    logger.info("")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())