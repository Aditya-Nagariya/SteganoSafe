import os
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WSGI")

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    # Import app and related components
    from app import app, socketio, db, create_default_admin
    
    # Initialize database and create admin user
    with app.app_context():
        logger.info("Creating database tables...")
        db.create_all()
        logger.info("Database tables created")
        create_default_admin()
except Exception as e:
    logger.error(f"Error during initialization: {str(e)}")
    # Keep going, as we want the app to start regardless

# This enables both gunicorn and direct running
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    socketio.run(app, host="0.0.0.0", port=port)
