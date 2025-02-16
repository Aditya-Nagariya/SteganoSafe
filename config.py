from dotenv import load_dotenv
import os
from datetime import timedelta

# Ensure .env is loaded early
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "default-secret-key"
    WTF_CSRF_SECRET_KEY = os.getenv('CSRF_SECRET_KEY', 'csrf-dev-key')
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///app.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER") or "uploads"
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    # In production, sessions should be secure so cookies are sent only over HTTPS.
    SESSION_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    WTF_CSRF_ENABLED = True
    DEBUG = os.getenv('FLASK_DEBUG', 'True') == 'True'
    SQLALCHEMY_ECHO = DEBUG  # Enable SQL logging in debug mode
    CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL") or "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND") or "redis://localhost:6379/0"
    # IMPORTANT: For development, force tasks to execute synchronously to avoid broker connection errors.
    CELERY_TASK_ALWAYS_EAGER = True  # Force tasks to execute synchronously in development
    # Force URL generation to use HTTPS in production
    PREFERRED_URL_SCHEME = 'https' if os.getenv('FLASK_ENV') == 'production' else 'http'
    # Add Twilio credentials
    TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
    TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")