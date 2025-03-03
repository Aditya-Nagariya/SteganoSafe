from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from models import db, User, ActivityLog
from forms import RegisterForm
from flask_login import current_user
import re
import logging

auth_bp = Blueprint('auth', __name__)

# New standalone registration route with better error handling
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    
    # For development, make OTP check optional
    if request.method == 'POST':
        logging.debug("Processing registration form")
        
        # For debugging, log all non-password fields
        for field_name, value in request.form.items():
            if 'password' not in field_name.lower():
                logging.debug(f"Form field {field_name}: {value}")
    
    # Validate form
    if form.validate_on_submit():
        try:
            # Check if username already exists
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already taken', 'danger')
                return render_template('register.html', form=form)
            
            # Check if email already exists
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered', 'danger')
                return render_template('register.html', form=form)
            
            # Clean phone number if provided
            phone = form.clean_phone_number()
            
            # Check if phone already exists (if provided)
            if phone and User.query.filter_by(phone_number=phone).first():
                flash('Phone number already registered', 'danger')
                return render_template('register.html', form=form)
            
            # Create new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                phone_number=phone,
                is_verified=True  # Auto-verify in development
            )
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.commit()
            
            # Log activity
            activity = ActivityLog(
                user_id=user.id,
                action="User registered"
            )
            db.session.add(activity)
            db.session.commit()
            
            flash('Registration successful! Please log in', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            logging.exception(f"Registration error: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
    
    elif request.method == 'POST':
        # Log validation errors
        logging.debug(f"Form validation errors: {form.errors}")
        
    return render_template('register.html', form=form)

# Directory structure must be registered in app.py:
# from routes import auth_bp
# app.register_blueprint(auth_bp, url_prefix='/auth')
