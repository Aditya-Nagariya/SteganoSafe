#!/usr/bin/env python3
"""
Admin initialization script for SteganoSafe.
Creates necessary admin user and sample data for testing.
"""
import os
import sys
import logging
from flask import Flask
from datetime import datetime, timedelta
import random

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add the current directory to the path for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    # Import app modules
    from models import db, User, StegoImage, ActivityLog
    from config import Config
except ImportError as e:
    logger.error(f"Import error: {e}. Make sure you're running this from the app directory.")
    sys.exit(1)

def create_app():
    """Create a Flask app instance for setup"""
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app

def create_admin_user(app):
    """Create admin user if not exists"""
    with app.app_context():
        # Check if admin exists
        admin = User.query.filter_by(role='admin').first()
        if admin:
            logger.info(f"Admin user already exists: {admin.username}")
            return admin
            
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin',
            is_verified=True,
            phone_number='+1234567890'
        )
        admin.set_password('admin123')
        
        db.session.add(admin)
        db.session.commit()
        logger.info("Created admin user 'admin' with password 'admin123'")
        return admin

def create_sample_users(app, count=5):
    """Create sample users"""
    with app.app_context():
        current_count = User.query.filter(User.role != 'admin').count()
        if current_count >= count:
            logger.info(f"Already have {current_count} sample users")
            return
            
        # Sample user data
        usernames = ['user1', 'user2', 'user3', 'user4', 'user5', 
                    'alice', 'bob', 'charlie', 'david', 'emma']
        domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'example.com']
        
        # Create only the additional users needed
        needed = count - current_count
        for i in range(needed):
            username = usernames[i % len(usernames)]
            # Add a random number to avoid duplicates
            if User.query.filter_by(username=username).first():
                username = f"{username}{random.randint(1, 999)}"
                
            user = User(
                username=username,
                email=f"{username}@{random.choice(domains)}",
                role='user',
                is_verified=random.choice([True, True, False]),  # 2/3 chance of being verified
                phone_number=f"+1{random.randint(1000000000, 9999999999)}"
            )
            user.set_password('password123')
            db.session.add(user)
            
        db.session.commit()
        logger.info(f"Created {needed} sample users")

def create_sample_activities(app, count_per_user=3):
    """Create sample activity logs"""
    with app.app_context():
        users = User.query.all()
        
        # Sample activities
        actions = [
            "User logged in",
            "Password changed",
            "Profile updated",
            "Image uploaded",
            "Image encrypted",
            "Image decrypted",
            "Failed login attempt",
            "Email verified",
            "Account settings changed"
        ]
        
        # IP addresses
        ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '8.8.8.8', '1.1.1.1']
        
        # User agents
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15"
        ]
        
        for user in users:
            # Check if this user already has activities
            existing = ActivityLog.query.filter_by(user_id=user.id).count()
            if existing >= count_per_user:
                continue
                
            needed = count_per_user - existing
            for i in range(needed):
                # Random time in the last week
                timestamp = datetime.utcnow() - timedelta(
                    days=random.randint(0, 7),
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59)
                )
                
                activity = ActivityLog(
                    user_id=user.id,
                    action=random.choice(actions),
                    timestamp=timestamp,
                    ip_address=random.choice(ips),
                    user_agent=random.choice(user_agents)
                )
                db.session.add(activity)
                
        db.session.commit()
        logger.info(f"Created sample activities for users")

def main():
    """Main function to initialize the admin system"""
    logger.info("Starting admin initialization...")
    
    try:
        app = create_app()
        
        # Create tables if they don't exist
        with app.app_context():
            db.create_all()
            logger.info("Database tables created")
        
        # Create admin user and sample data
        admin = create_admin_user(app)
        create_sample_users(app, count=5)
        create_sample_activities(app, count_per_user=10)
        
        logger.info("Admin initialization completed successfully")
        print("\n" + "-" * 60)
        print("SteganoSafe Admin Initialization Complete")
        print("-" * 60)
        print("Admin User: admin")
        print("Admin Password: admin123")
        print("Access the admin dashboard at: /admin")
        print("-" * 60 + "\n")
        
    except Exception as e:
        logger.error(f"Error during initialization: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
