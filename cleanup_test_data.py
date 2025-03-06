#!/usr/bin/env python3
"""
Script to clean up test data for analytics dashboard.
This removes fake users, images, and activity logs for a clean slate.
"""
import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def cleanup_test_data():
    """Clean up test data from the application database"""
    from app import app
    from models import db, User, StegoImage, ActivityLog
    
    with app.app_context():
        logger.info("Starting test data cleanup...")
        
        # Keep count of deleted items
        deleted_users = 0
        deleted_images = 0
        deleted_activities = 0
        
        # Delete test users (except admin)
        test_users = User.query.filter(User.username.like('test_user_%')).all()
        for user in test_users:
            # Delete all activity logs for this user
            user_logs = ActivityLog.query.filter_by(user_id=user.id).all()
            for log in user_logs:
                db.session.delete(log)
                deleted_activities += 1
            
            # Delete all images for this user
            user_images = StegoImage.query.filter_by(user_id=user.id).all()
            for image in user_images:
                db.session.delete(image)
                deleted_images += 1
            
            # Delete the user
            db.session.delete(user)
            deleted_users += 1
        
        # Delete test images (with test_image in filename)
        test_images = StegoImage.query.filter(StegoImage.original_filename.like('test_image_%')).all()
        for image in test_images:
            db.session.delete(image)
            deleted_images += 1
        
        # Commit the changes
        db.session.commit()
        
        logger.info(f"Cleanup complete: Deleted {deleted_users} users, {deleted_images} images, and {deleted_activities} activity logs")
        
        # Print summary of remaining data
        remaining_users = User.query.count()
        remaining_images = StegoImage.query.count()
        remaining_activities = ActivityLog.query.count()
        
        logger.info("=== Remaining Data ===")
        logger.info(f"Users: {remaining_users}")
        logger.info(f"Images: {remaining_images}")
        logger.info(f"Activities: {remaining_activities}")
        
        return {
            'deleted': {
                'users': deleted_users,
                'images': deleted_images,
                'activities': deleted_activities
            },
            'remaining': {
                'users': remaining_users,
                'images': remaining_images,
                'activities': remaining_activities
            }
        }

if __name__ == "__main__":
    # Ask for confirmation before proceeding
    confirm = input("This will delete all test data. Are you sure? (yes/no): ")
    
    if confirm.lower() == 'yes':
        result = cleanup_test_data()
        print(f"Cleanup complete! Deleted {result['deleted']['users']} test users, {result['deleted']['images']} test images, and {result['deleted']['activities']} activity logs.")
    else:
        print("Cleanup cancelled.")
