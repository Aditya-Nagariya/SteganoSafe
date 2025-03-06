#!/usr/bin/env python3
"""
Setup script for SteganoSafe analytics module.

This script installs the required dependencies for the analytics features.
Run this script before using the analytics dashboard.
"""
import os
import sys
import subprocess
import logging
import importlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ANALYTICS_SETUP")

# Required packages for analytics features
REQUIRED_PACKAGES = [
    'pandas',
    'numpy',
    'plotly',  # For advanced visualizations
    'psutil',  # For system monitoring
]

def check_installed(package):
    """Check if a package is installed"""
    try:
        importlib.import_module(package)
        return True
    except ImportError:
        return False

def is_virtualenv():
    """Check if running inside a virtual environment"""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

def install_packages():
    """Install required Python packages"""
    missing_packages = [pkg for pkg in REQUIRED_PACKAGES if not check_installed(pkg)]
    
    if not missing_packages:
        logger.info("All required packages already installed.")
        return True
    
    logger.info(f"Installing required packages: {', '.join(missing_packages)}")
    
    # Don't use --user flag if in a virtualenv
    pip_args = [sys.executable, "-m", "pip", "install"]
    if not is_virtualenv():
        # Only use --user for system Python to avoid permission issues
        pip_args.append("--user")
    
    # Add the packages to install
    pip_args.extend(missing_packages)
    
    try:
        # Show the command we're running for debugging
        logger.info(f"Running: {' '.join(pip_args)}")
        subprocess.check_call(pip_args)
        logger.info("Packages installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install packages: {e}")
        return False

def main():
    """Main function"""
    print("SteganoSafe Analytics Setup")
    print("==========================")
    print("This script will install the required dependencies for the analytics features.")
    
    try:
        # Log environment info for debugging
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Python executable: {sys.executable}")
        logger.info(f"Running in virtualenv: {is_virtualenv()}")
        
        if install_packages():
            print("\nSetup complete! You can now use the analytics features.")
            
            # Remind about app restart
            print("\nIMPORTANT: If your app is already running, please restart it")
            print("to load the newly installed packages.")
            
            return 0
        else:
            print("\nSetup failed. Please check the error messages above.")
            print("You may need to manually install the required packages:")
            for pkg in REQUIRED_PACKAGES:
                print(f"  - {pkg}")
                
            # Suggest manual installation command
            cmd = f"{sys.executable} -m pip install {' '.join(REQUIRED_PACKAGES)}"
            print(f"\nYou can try manually running: {cmd}")
            
            return 1
    except Exception as e:
        logger.error(f"Unexpected error during setup: {e}")
        print(f"\nSetup failed due to an unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
