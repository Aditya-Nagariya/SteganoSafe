import os
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DB_INIT")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    logger.info("Initializing database...")
    
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    logger.info("Data directory created/verified")
    
    # Import your app and database
    from app import app, db
    from models import User, StegoImage, ActivityLog
    
    with app.app_context():
        logger.info("Creating database tables...")
        db.create_all()
        logger.info("Database tables created")
        
        # Create default admin user
        admin_exists = User.query.filter_by(role='admin').first()
        
        if not admin_exists:
            logger.info("Creating default admin user...")
            from werkzeug.security import generate_password_hash
            
            admin = User(
                username='admin',
                email='admin@example.com',
                phone_number='+1234567890',
                password_hash=generate_password_hash('admin123'),
                is_verified=True,
                role='admin'
            )
            
            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin user created")
            
    logger.info("Database initialization complete!")
    
except Exception as e:
    logger.error(f"Error initializing database: {str(e)}")
    raise
