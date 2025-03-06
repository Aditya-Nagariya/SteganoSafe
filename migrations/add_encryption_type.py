"""
Migration script to add encryption_type column to stego_images table.
This can be run manually to update the database schema.
"""
import os
import sys
import logging

# Append parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from models import db, StegoImage
from sqlalchemy import Column, String

def run_migration():
    """Add encryption_type column to StegoImage table if it doesn't exist"""
    try:
        # Create a minimal Flask app
        app = Flask(__name__)
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///steganography_app.db')
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(app)
        
        with app.app_context():
            # Check if the column exists
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('stego_images')]
            
            if 'encryption_type' not in columns:
                print("Adding encryption_type column to stego_images table...")
                # Add the column
                db.engine.execute('ALTER TABLE stego_images ADD COLUMN encryption_type VARCHAR(20) DEFAULT "LSB"')
                print("Column added successfully!")
            else:
                print("Column 'encryption_type' already exists in stego_images table.")
                
            # Update any NULL values
            db.engine.execute('UPDATE stego_images SET encryption_type = "LSB" WHERE encryption_type IS NULL')
            print("Successfully updated NULL encryption_type values to 'LSB'")
            
        return True
    except Exception as e:
        print(f"Error during migration: {str(e)}")
        return False

if __name__ == '__main__':
    success = run_migration()
    if success:
        print("Migration completed successfully")
    else:
        print("Migration failed")
        sys.exit(1)
