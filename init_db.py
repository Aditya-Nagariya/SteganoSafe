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
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    os.makedirs(data_dir, exist_ok=True)
    logger.info(f"Data directory created/verified at {data_dir}")
    
    # Check if database file exists
    db_path = os.path.join(data_dir, 'app.db')
    logger.info(f"Database path: {db_path}")
    
    # Import Flask app and database
    from app import app, db
    
    # Import models to ensure they're registered with SQLAlchemy
    from models import User, StegoImage, ActivityLog
    
    with app.app_context():
        logger.info("Creating database tables...")
        db.create_all()
        logger.info("Database tables created")
        
        # Verify table creation by checking if the users table exists
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        logger.info(f"Created tables: {tables}")
        
        if 'user' not in tables and 'users' not in tables:
            logger.error("Users table not created! Check database configuration.")
        
        # Create default admin user
        try:
            admin_exists = User.query.filter_by(role='admin').first()
            
            if not admin_exists:
                logger.info("Creating default admin user...")
                
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    phone_number='+1234567890',
                    is_verified=True,
                    role='admin'
                )
                admin.set_password('admin123')
                
                db.session.add(admin)
                db.session.commit()
                logger.info("Default admin user created")
            else:
                logger.info("Admin user already exists")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating admin user: {str(e)}")
    
    logger.info("Database initialization complete!")
    
except Exception as e:
    logger.error(f"Error initializing database: {str(e)}")
    import traceback
    logger.error(traceback.format_exc())
    # In the init script, we should raise the error to prevent the app from starting with a bad DB
    raise
