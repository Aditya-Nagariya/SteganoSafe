"""
User profile routes for SteganoSafe application.
This includes the profile page and user settings.
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from models import db, User, ActivityLog
import logging

# Setup logging
logger = logging.getLogger(__name__)

# Create blueprint with a url_prefix to avoid route conflicts
user_bp = Blueprint('user_bp', __name__, url_prefix='/user')

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

@user_bp.route('/settings', methods=['GET', 'POST'])
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
    logger.info("Registering user routes")
    app.register_blueprint(user_bp)
    
    # DO NOT register a duplicate /profile route 
    # The main app.py already has this route defined
    # Instead, mention in a log that we found it
    logger.info("Note: /profile route should be configured in main app.py to redirect to user_bp.profile")
    
    # If you want to provide a utility function the main app can use:
    def get_profile_redirect():
        """Helper function that can be imported in app.py to redirect to the profile page"""
        return redirect(url_for('user_bp.profile'))
    
    # Attach the function to the app for use in app.py
    app.get_profile_redirect = get_profile_redirect
