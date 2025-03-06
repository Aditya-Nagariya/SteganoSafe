#!/usr/bin/env python3
"""
Script to generate test data for analytics dashboard.
This creates fake users, images, and activity logs for demonstration purposes.
"""
import os
import sys
import random
import datetime
from flask import Flask
from io import BytesIO
from PIL import Image
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def create_random_image(width=100, height=100):
    """Create a random image for testing"""
    # Generate random colors
    color = (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )
    bg_color = (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )
    
    # Create a new image with random background
    img = Image.new('RGB', (width, height), bg_color)
    
    # Draw a simple shape
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    
    shape_type = random.choice(['rectangle', 'circle', 'line'])
    
    if shape_type == 'rectangle':
        x1 = random.randint(0, width // 3)
        y1 = random.randint(0, height // 3)
        x2 = random.randint(2 * width // 3, width)
        y2 = random.randint(2 * height // 3, height)
        draw.rectangle([x1, y1, x2, y2], fill=color)
    elif shape_type == 'circle':
        x = random.randint(width // 4, 3 * width // 4)
        y = random.randint(height // 4, 3 * height // 4)
        radius = random.randint(min(width, height) // 8, min(width, height) // 4)
        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color)
    else:  # line
        x1 = random.randint(0, width // 2)
        y1 = random.randint(0, height // 2)
        x2 = random.randint(width // 2, width)
        y2 = random.randint(height // 2, height)
        draw.line((x1, y1, x2, y2), fill=color, width=5)
    
    # Save to BytesIO
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return img_io.getvalue()

def generate_test_data(num_users=5, num_images=15, num_activities=50):
    """Generate test data for the application"""
    from app import app
    from models import db, User, StegoImage, ActivityLog
    
    with app.app_context():
        logger.info("Generating test data...")
        
        # Create users if needed
        existing_users = User.query.count()
        admin_user_id = None
        
        if existing_users == 0:
            logger.info("No existing users found. Creating admin user.")
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
            admin_user_id = admin.id
        else:
            admin_user = User.query.filter_by(role='admin').first()
            if admin_user:
                admin_user_id = admin_user.id
        
        # Create regular test users
        users = []
        for i in range(num_users):
            username = f"test_user_{i+1}"
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                logger.info(f"User {username} already exists, skipping.")
                continue
                
            user = User(
                username=username,
                email=f"user{i+1}@example.com",
                phone_number=f"+1{random.randint(1000000000, 9999999999)}",
                is_verified=True,
                role='user',
                created_at=datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 30))
            )
            user.set_password('password123')
            db.session.add(user)
            users.append(username)
        db.session.commit()
        
        # Get all users
        all_users = User.query.all()
        user_ids = [user.id for user in all_users]
        
        # Create random images
        images = []
        for i in range(num_images):
            # Pick a random user
            user_id = random.choice(user_ids)
            
            image_data = create_random_image()
            original_filename = f"test_image_{i+1}.png"
            unique_filename = f"{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{i}_{original_filename}"
            
            # Create image record
            image = StegoImage(
                user_id=user_id,
                filename=unique_filename,
                original_filename=original_filename,
                image_data=image_data,
                encryption_type='LSB',
                created_at=datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 14))
            )
            db.session.add(image)
            images.append(unique_filename)
        db.session.commit()
        
        # Create random activity logs
        for i in range(num_activities):
            # Pick a random user
            user_id = random.choice(user_ids)
            
            # Generate a random timestamp in the last 14 days
            timestamp = datetime.datetime.now() - datetime.timedelta(
                days=random.randint(0, 13),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            # Random action type
            action_type = random.choice(['login', 'encrypt', 'decrypt', 'view', 'download'])
            
            if action_type == 'login':
                action_text = "User logged in"
            elif action_type == 'encrypt':
                action_text = f"Encrypted image: test_image_{random.randint(1, num_images)}.png"
            elif action_type == 'decrypt':
                action_text = f"Decrypted image: test_image_{random.randint(1, num_images)}.png"
            elif action_type == 'view':
                action_text = "Viewed dashboard"
            elif action_type == 'download':
                action_text = f"Downloaded image: test_image_{random.randint(1, num_images)}.png"
            
            # Create activity log
            activity = ActivityLog(
                user_id=user_id,
                action=action_text,
                timestamp=timestamp,
                ip_address=f"192.168.1.{random.randint(2, 254)}"
            )
            db.session.add(activity)
        
        db.session.commit()
        
        logger.info(f"Generated {len(users)} users, {len(images)} images, and {num_activities} activity logs")
        
        # Print summary
        logger.info("=== Data Generation Summary ===")
        logger.info(f"Total Users: {User.query.count()}")
        logger.info(f"Total Images: {StegoImage.query.count()}")
        logger.info(f"Total Activities: {ActivityLog.query.count()}")
        
        return True

if __name__ == "__main__":
    generate_test_data()
    print("Test data generation complete!")
