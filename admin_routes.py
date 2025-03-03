"""
Admin routes for the SteganoSafe application.
"""
from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from models import db, User, StegoImage, ActivityLog
import logging
import traceback
import os
from datetime import datetime
from functools import wraps

# Configure logging
logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin_bp', __name__)

def admin_required(f):
    """Decorator to require admin role for a route"""
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.role == 'admin':
            logger.warning(f"Non-admin user {current_user.username} attempted to access admin area")
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    
    # Preserve the function metadata
    decorated_function.__name__ = f.__name__
    return decorated_function

@admin_bp.route('/')
@admin_required
def index():
    """Admin dashboard index"""
    try:
        # Get counts for summary
        user_count = User.query.count()
        image_count = StegoImage.query.count()
        activity_count = ActivityLog.query.count()
        
        # Get recent activity
        recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
        
        return render_template(
            'admin/index.html',
            user_count=user_count,
            image_count=image_count,
            activity_count=activity_count,
            recent_activities=recent_activities
        )
    except Exception as e:
        logger.error(f"Error in admin index: {str(e)}")
        logger.error(traceback.format_exc())
        flash(f"An error occurred: {str(e)}", "danger")
        return render_template('admin/error.html', error=str(e))

@admin_bp.route('/users')
@admin_required
def users():
    """List all users"""
    try:
        users = User.query.all()
        return render_template('admin/users.html', users=users)
    except Exception as e:
        logger.error(f"Error in admin users: {str(e)}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('admin_bp.index'))

@admin_bp.route('/images')
@admin_required
def images():
    """List all images"""
    try:
        images = StegoImage.query.all()
        return render_template('admin/images.html', images=images)
    except Exception as e:
        logger.error(f"Error in admin images: {str(e)}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('admin_bp.index'))

@admin_bp.route('/activity')
@admin_required
def activity():
    """View activity logs"""
    try:
        logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
        return render_template('admin/activity.html', logs=logs)
    except Exception as e:
        logger.error(f"Error in admin activity: {str(e)}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('admin_bp.index'))

@admin_bp.route('/status')
@admin_required
def status():
    """System status endpoint for admins"""
    try:
        import platform
        import psutil
        
        # System info
        system_info = {
            'platform': platform.platform(),
            'python': platform.python_version(),
            'cpu_count': os.cpu_count(),
            'process_memory_mb': round(psutil.Process().memory_info().rss / (1024 * 1024), 2) if 'psutil' in sys.modules else 'N/A'
        }
        
        # Database stats
        db_stats = {
            'users': User.query.count(),
            'images': StegoImage.query.count(),
            'activities': ActivityLog.query.count()
        }
        
        return jsonify({
            'success': True,
            'system': system_info,
            'database': db_stats,
            'time': str(datetime.utcnow())
        })
    except Exception as e:
        logger.error(f"Error in admin status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
