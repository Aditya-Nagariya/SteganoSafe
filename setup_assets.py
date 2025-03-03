#!/usr/bin/env python
"""
Script to generate all static assets for the SteganoSafe application.
Run this script to create:
- Hero image for the homepage
- Favicon
- Default admin user
"""
import os
import sys

# Ensure 'static' directory exists
os.makedirs('static', exist_ok=True)
os.makedirs(os.path.join('static', 'img'), exist_ok=True)

# Create hero image
print("Creating hero image...")
try:
    from create_hero_image import create_hero_image
    hero_path = create_hero_image()
    print(f"Hero image created: {hero_path}")
except Exception as e:
    print(f"Error creating hero image: {e}")

# Create favicon
print("\nCreating favicon...")
try:
    from create_favicon import create_favicon
    create_favicon()
    print("Favicon created successfully")
except Exception as e:
    print(f"Error creating favicon: {e}")

# Create default admin user
print("\nSetting up default admin user...")
try:
    # Since this requires the Flask app to be configured,
    # we'll import directly from app.py
    sys.path.insert(0, os.getcwd())
    from app import app, create_default_admin
    
    with app.app_context():
        create_default_admin()
        
    print("Admin user configuration complete")
except Exception as e:
    print(f"Error setting up admin user: {e}")
    print("You may need to run the app first to create database tables")

print("\nAsset setup complete!")
print("\nTo run the application:")
print("1. Ensure database is initialized: flask db init (if needed)")
print("2. Run the app: python app.py --debug")
print("\nDefault admin credentials:")
print("  Username: admin")
print("  Password: admin123")
