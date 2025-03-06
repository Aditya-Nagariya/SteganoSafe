"""
Configuration settings for the SteganoSafe application.
"""
from dotenv import load_dotenv
import os
import secrets
from datetime import timedelta
import logging
from contextlib import suppress
import json

# Ensure .env is loaded early
load_dotenv()

# Setup logger
logger = logging.getLogger(__name__)

# Path to config file for persistent settings
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'app_config.json')

class Config:
    # Create data directory if it doesn't exist
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    # Try to set permissions but don't fail if it doesn't work
    with suppress(Exception):
        os.chmod(data_dir, 0o777)
    
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or secrets.token_hex(16)
    DEBUG = os.getenv('FLASK_DEBUG', 'True') == 'True'
    TESTING = os.environ.get('FLASK_TESTING') == 'True'
    
    # Database - use the environment variable or fall back to our data dir
    db_uri = os.environ.get('DATABASE_URL')
    if not db_uri:
        db_path = os.path.join(data_dir, 'app.db')
        db_uri = f'sqlite:///{db_path}'
        # Log the database URI we're using
        logger.info(f"Using database at: {db_path}")
        
    SQLALCHEMY_DATABASE_URI = db_uri
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload configuration
    UPLOAD_FOLDER = os.path.join(data_dir, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
    
    # Email configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'yes', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@steganosafe.com'
    
    # Celery configuration
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/0'
    CELERY_TASK_ALWAYS_EAGER = True  # Force tasks to execute synchronously in development
    
    # Session configuration - modify these settings
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)  # Extend to 7 days
    SESSION_COOKIE_SECURE = False  # Set to False for development
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # Use 'Lax' for login redirects to work
    
    # CSRF settings
    WTF_CSRF_SECRET_KEY = os.getenv('CSRF_SECRET_KEY', 'csrf-dev-key')
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour in seconds
    
    # Development settings
    DEBUG = os.environ.get('FLASK_DEBUG', '').lower() in ['true', '1']
    TESTING = os.environ.get('FLASK_TESTING', '').lower() in ['true', '1']
    
    # Admin User Default Credentials
    DEFAULT_ADMIN_USERNAME = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
    DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
    DEFAULT_ADMIN_EMAIL = os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
    DEFAULT_ADMIN_PHONE = os.environ.get('DEFAULT_ADMIN_PHONE', '+1234567890')
    
    # Other Config
    SQLALCHEMY_ECHO = DEBUG  # Enable SQL logging in debug mode
    PREFERRED_URL_SCHEME = 'https' if os.getenv('FLASK_ENV') == 'production' else 'http'
    TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
    TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")
    
    # Email validation settings
    SKIP_EMAIL_DOMAIN_CHECK = True  # Set to False in production
    ALLOWED_TEST_DOMAINS = ['example.com', 'example.org', 'example.net', 'test.com']
    
    # Steganography settings
    DEFAULT_ENCRYPTION_METHOD = 'LSB'
    
    # Load custom settings from file if exists
    @classmethod
    def load_from_file(cls):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    custom_config = json.load(f)
                
                for key, value in custom_config.items():
                    setattr(cls, key, value)
                    
                logger.info(f"Loaded custom config from {CONFIG_FILE}")
            except Exception as e:
                logger.error(f"Error loading config file: {str(e)}")

# Load custom config at module import
Config.load_from_file()

def update_config(key, value):
    """Update a configuration value both in memory and in file"""
    # Update in the current running instance
    setattr(Config, key, value)
    
    try:
        # Read current config file
        import os
        config_path = os.path.join(os.path.dirname(__file__), 'config.py')
        with open(config_path, 'r') as file:
            config_content = file.readlines()
        
        # Find the line with the setting or append to the end
        found = False
        for i, line in enumerate(config_content):
            if line.strip().startswith(f"{key} ="):
                if isinstance(value, str):
                    config_content[i] = f"{key} = '{value}'\n"
                else:
                    config_content[i] = f"{key} = {value}\n"
                found = True
                break
        
        if not found:
            # Add new setting to the end of the file
            if isinstance(value, str):
                config_content.append(f"{key} = '{value}'\n")
            else:
                config_content.append(f"{key} = {value}\n")
        
        # Write updated content back to file
        with open(config_path, 'w') as file:
            file.writelines(config_content)
            
        return True
    except Exception as e:
        import logging
        logging.error(f"Failed to update config file: {str(e)}")
        return False