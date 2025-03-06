"""
User profile routes for SteganoSafe application.
This includes the profile page and user settings.
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from models import db, User, ActivityLog
import logging

# Create blueprint
user_bp = Blueprint('user_bp', __name__)

@user_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    # Get user's recent activity
    activities = ActivityLog.query.filter_by(user_id=current_user.id)\
                                .order_by(ActivityLog.timestamp.desc())\
                                .limit(10).all()
    
    return render_template('profile.html', 
                          user=current_user,
                          activities=activities)

@user_bp.route('/profile/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page"""
    if request.method == 'POST':
        # Process form data
        email = request.form.get('email')
        phone = request.form.get('phone')
        
        # Update user
        if email and email != current_user.email:
            # Check if email already exists
            existing = User.query.filter(User.id != current_user.id, User.email == email).first()
            if existing:
                flash('Email already in use', 'danger')
            else:
                current_user.email = email
                db.session.commit()
                flash('Email updated successfully', 'success')
                
        if phone != current_user.phone_number:
            current_user.phone_number = phone
            db.session.commit()
            flash('Phone number updated successfully', 'success')
                
        return redirect(url_for('user_bp.settings'))
        
    return render_template('settings.html', user=current_user)

# This function should be called in app.py to register the blueprint
def init_user_routes(app):
    app.register_blueprint(user_bp)
    # Also register a direct route for the profile
    @app.route('/profile')
    @login_required
    def profile():
        return redirect(url_for('user_bp.profile'))
