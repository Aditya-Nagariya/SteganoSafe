#!/usr/bin/env python3
"""
Script to manually create an admin user.
Run this script directly to create an admin user with custom credentials.
"""

import os
import sys
import getpass
from flask import Flask
from models import db, User

# Import app configuration
sys.path.insert(0, os.getcwd())
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app

def create_admin(username, email, password, phone=None):
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User '{username}' already exists.")
            response = input("Update this user to admin role? (y/n): ")
            if response.lower() != 'y':
                print("Admin creation aborted.")
                return
            
            existing_user.role = 'admin'
            existing_user.set_password(password)
            if phone:
                existing_user.phone_number = phone
            db.session.commit()
            print(f"User '{username}' updated to admin role.")
            return
        
        # Create new admin user
        admin = User(
            username=username,
            email=email,
            phone_number=phone,
            is_verified=True,
            role='admin'
        )
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user '{username}' created successfully!")

if __name__ == "__main__":
    app = create_app()
    
    print("Create Admin User")
    print("----------------")
    
    # Get admin details
    username = input("Username (default: admin): ") or "admin"
    email = input("Email (default: admin@example.com): ") or "admin@example.com"
    phone = input("Phone (E.164 format, e.g. +1234567890): ")
    password = getpass.getpass("Password (default: admin123): ") or "admin123"
    password_confirm = getpass.getpass("Confirm password: ")
    
    if password != password_confirm:
        print("Passwords do not match. Admin creation aborted.")
        sys.exit(1)
    
    create_admin(username, email, password, phone)
