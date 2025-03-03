"""
Admin routes for the SteganoSafe application.
"""
from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, User, StegoImage, ActivityLog
import logging
from functools import wraps

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    """Decorator to require admin role for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/')
@admin_required
def admin_dashboard():
    """Admin dashboard homepage"""
    user_count = User.query.count()
    image_count = StegoImage.query.count()
    activity_count = ActivityLog.query.count()
    
    return render_template(
        'admin/dashboard.html',
        user_count=user_count,
        image_count=image_count,
        activity_count=activity_count
    )

@admin_bp.route('/users')
@admin_required
def user_list():
    """List all users"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/<int:user_id>')
@admin_required
def user_detail(user_id):
    """View details for a specific user"""
    user = User.query.get_or_404(user_id)
    images = StegoImage.query.filter_by(user_id=user.id).all()
    activities = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc()).limit(50).all()
    
    return render_template(
        'admin/user_detail.html',
        user=user,
        images=images,
        activities=activities
    )

@admin_bp.route('/analytics')
@admin_required
def analytics():
    """View analytics dashboard"""
    return render_template('admin/analytics.html')

@admin_bp.route('/logs')
@admin_required
def view_logs():
    """View application logs"""
    try:
        with open('app.log', 'r') as f:
            logs = f.readlines()
        return render_template('admin/logs.html', logs=logs[-500:])  # Show last 500 lines
    except Exception as e:
        logging.error(f"Error reading logs: {e}")
        return render_template('admin/logs.html', logs=["Error reading log file"])

@admin_bp.route('/api/user-stats')
@admin_required
def user_stats_api():
    """API endpoint for user statistics"""
    total_users = User.query.count()
    verified_users = User.query.filter_by(is_verified=True).count()
    admin_users = User.query.filter_by(role='admin').count()
    
    # Users by day (last 30 days)
    from sqlalchemy import func
    import datetime
    
    thirty_days_ago = datetime.datetime.now() - datetime.timedelta(days=30)
    
    user_registrations = db.session.query(
        func.date(User.created_at).label('date'),
        func.count().label('count')
    ).filter(User.created_at >= thirty_days_ago).group_by(func.date(User.created_at)).all()
    
    registration_data = {
        'labels': [str(row.date) for row in user_registrations],
        'data': [row.count for row in user_registrations]
    }
    
    return jsonify({
        'total_users': total_users,
        'verified_users': verified_users,
        'admin_users': admin_users,
        'registrations_by_day': registration_data
    })

@admin_bp.route('/api/image-stats')
@admin_required
def image_stats_api():
    """API endpoint for image statistics"""
    total_images = StegoImage.query.count()
    
    # Images by user (top 10)
    from sqlalchemy import func
    
    image_counts = db.session.query(
        User.username.label('username'),
        func.count(StegoImage.id).label('count')
    ).join(StegoImage, StegoImage.user_id == User.id)\
        .group_by(User.username)\
        .order_by(func.count(StegoImage.id).desc())\
        .limit(10).all()
    
    user_data = {
        'labels': [row.username for row in image_counts],
        'data': [row.count for row in image_counts]
    }
    
    return jsonify({
        'total_images': total_images,
        'images_by_user': user_data
    })

@admin_bp.route('/users/<int:user_id>/change-role/<string:role>', methods=['GET', 'POST'])
@admin_required
def change_user_role(user_id, role):
    """Change a user's role"""
    if role not in ['admin', 'mod', 'user']:
        flash("Invalid role specified", "danger")
        return redirect(url_for('admin.user_list'))
        
    user = User.query.get_or_404(user_id)
    
    # Don't let admins remove their own admin status
    if user.id == current_user.id and role != 'admin':
        flash("You cannot remove your own admin status", "danger")
        return redirect(url_for('admin.user_list'))
    
    # Update role
    old_role = user.role
    user.role = role
    db.session.commit()
    
    # Log activity
    activity = ActivityLog(
        user_id=current_user.id,
        action=f"Changed user {user.username} role from {old_role} to {role}"
    )
    db.session.add(activity)
    db.session.commit()
    
    flash(f"User {user.username} role changed to {role}", "success")
    return redirect(url_for('admin.user_list'))

@admin_bp.route('/users/<int:user_id>/verify', methods=['GET'])
@admin_required
def verify_user(user_id):
    """Mark a user as verified"""
    user = User.query.get_or_404(user_id)
    
    user.is_verified = True
    db.session.commit()
    
    # Log activity
    activity = ActivityLog(
        user_id=current_user.id,
        action=f"Verified user {user.username}"
    )
    db.session.add(activity)
    db.session.commit()
    
    flash(f"User {user.username} has been verified", "success")
    return redirect(url_for('admin.user_list'))

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user"""
    user = User.query.get_or_404(user_id)
    
    # Don't let admins delete themselves
    if user.id == current_user.id:
        flash("You cannot delete your own account", "danger")
        return redirect(url_for('admin.user_list'))
    
    # Log activity before deleting
    activity = ActivityLog(
        user_id=current_user.id,
        action=f"Deleted user {user.username} (ID: {user.id})"
    )
    db.session.add(activity)
    
    # Delete user's images
    images = StegoImage.query.filter_by(user_id=user.id).all()
    for image in images:
        db.session.delete(image)
    
    # Delete user's activity logs
    user_logs = ActivityLog.query.filter_by(user_id=user.id).all()
    for log in user_logs:
        db.session.delete(log)
    
    # Delete the user
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User {username} has been deleted", "success")
    return redirect(url_for('admin.user_list'))

# Fix the is_admin property in User model
@property
def is_admin(self):
    """Check if the user has admin role"""
    return self.role == 'admin'

# Promote user to admin
@admin_bp.route('/users/<int:user_id>/promote', methods=['GET', 'POST'])
@login_required
@admin_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.role == 'admin':
        flash(f'{user.username} is already an admin', 'info')
    else:
        user.role = 'admin'
        db.session.commit()
        flash(f'{user.username} has been promoted to admin', 'success')
        
    return redirect(url_for('admin.user_detail', user_id=user_id))

# Demote user to regular user
@admin_bp.route('/users/<int:user_id>/demote', methods=['GET', 'POST'])
@login_required
@admin_required
def demote_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Don't allow demoting yourself
    if user.id == current_user.id:
        flash('You cannot demote yourself!', 'danger')
        return redirect(url_for('admin.user_list'))
    
    if user.role != 'admin':
        flash(f'{user.username} is not an admin', 'info')
    else:
        user.role = 'user'
        db.session.commit()
        flash(f'{user.username} has been demoted to regular user', 'success')
        
    return redirect(url_for('admin.user_detail', user_id=user_id))

@admin_bp.route('/metrics')
@login_required
@admin_required
def metrics():
    """Return metrics data for the admin dashboard"""
    user_count = User.query.count()
    image_count = StegoImage.query.count()
    log_file = 'app.log'
    
    # Get activity count from the database
    activity_count = ActivityLog.query.count()
    
    # Get recent registrations (last 30 days)
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_registrations = User.query.filter(User.created_at >= thirty_days_ago).count()
    
    # Get activity stats
    from sqlalchemy import func
    login_count = ActivityLog.query.filter(ActivityLog.action.like('%logged in%')).count()
    encryption_count = ActivityLog.query.filter(ActivityLog.action.like('%Encrypted%')).count()
    decryption_count = ActivityLog.query.filter(ActivityLog.action.like('%decrypted%')).count()
    
    return jsonify({
        'user_count': user_count,
        'image_count': image_count,
        'activity_count': activity_count,
        'recent_registrations': recent_registrations,
        'login_count': login_count,
        'encryption_count': encryption_count,
        'decryption_count': decryption_count
    })

@admin_bp.route('/api/analytics/summary')
@login_required
@admin_required
def analytics_summary():
    """API endpoint for analytics summary data"""
    from datetime import datetime, timedelta
    from sqlalchemy import func, desc
    
    try:
        # Time periods
        now = datetime.now()
        last_7_days = now - timedelta(days=7)
        last_30_days = now - timedelta(days=30)
        
        # User metrics
        new_users_7d = User.query.filter(User.created_at >= last_7_days).count()
        new_users_30d = User.query.filter(User.created_at >= last_30_days).count()
        
        # Activity metrics
        encryptions_7d = ActivityLog.query.filter(
            ActivityLog.timestamp >= last_7_days,
            ActivityLog.action.like('%Encrypted%')
        ).count()
        
        decryptions_7d = ActivityLog.query.filter(
            ActivityLog.timestamp >= last_7_days,
            ActivityLog.action.like('%decrypted%')
        ).count()
        
        # Active users (users with activity in last 7 days)
        active_users = db.session.query(ActivityLog.user_id)\
            .filter(ActivityLog.timestamp >= last_7_days)\
            .group_by(ActivityLog.user_id).count()
        
        # Calculate trends (compared to previous period)
        new_users_prev = User.query.filter(
            User.created_at >= (last_7_days - timedelta(days=7)),
            User.created_at < last_7_days
        ).count()
        
        encryptions_prev = ActivityLog.query.filter(
            ActivityLog.timestamp >= (last_7_days - timedelta(days=7)),
            ActivityLog.timestamp < last_7_days,
            ActivityLog.action.like('%Encrypted%')
        ).count()
        
        decryptions_prev = ActivityLog.query.filter(
            ActivityLog.timestamp >= (last_7_days - timedelta(days=7)),
            ActivityLog.timestamp < last_7_days,
            ActivityLog.action.like('%decrypted%')
        ).count()
        
        active_users_prev = db.session.query(ActivityLog.user_id)\
            .filter(
                ActivityLog.timestamp >= (last_7_days - timedelta(days=7)),
                ActivityLog.timestamp < last_7_days
            )\
            .group_by(ActivityLog.user_id).count()
        
        # Calculate trend percentages
        def calc_trend(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return ((current - previous) / previous) * 100
            
        user_trend = calc_trend(new_users_7d, new_users_prev)
        encryption_trend = calc_trend(encryptions_7d, encryptions_prev)
        decryption_trend = calc_trend(decryptions_7d, decryptions_prev)
        active_trend = calc_trend(active_users, active_users_prev)
        
        # Top users
        top_users = db.session.query(
            User.username,
            User.id,
            func.count(ActivityLog.id).label('activity_count')
        ).join(ActivityLog, ActivityLog.user_id == User.id)\
         .group_by(User.id)\
         .order_by(desc('activity_count'))\
         .limit(5)\
         .all()
         
        top_users_data = [
            {
                'username': user.username,
                'id': user.id,
                'activity_count': user.activity_count,
                'initials': user.username[:2].upper() if user.username else 'UN'
            }
            for user in top_users
        ]
        
        # Activity over time (last 14 days)
        fourteen_days_ago = now - timedelta(days=14)
        daily_activity = []
        
        for i in range(14):
            day = fourteen_days_ago + timedelta(days=i)
            next_day = day + timedelta(days=1)
            
            encryptions = ActivityLog.query.filter(
                ActivityLog.timestamp >= day,
                ActivityLog.timestamp < next_day,
                ActivityLog.action.like('%Encrypted%')
            ).count()
            
            decryptions = ActivityLog.query.filter(
                ActivityLog.timestamp >= day,
                ActivityLog.timestamp < next_day,
                ActivityLog.action.like('%decrypted%')
            ).count()
            
            daily_activity.append({
                'date': day.strftime('%Y-%m-%d'),
                'label': day.strftime('%b %d'),
                'encryptions': encryptions,
                'decryptions': decryptions
            })
        
        return jsonify({
            'success': True,
            'summary': {
                'new_users': new_users_7d,
                'new_users_trend': round(user_trend, 1),
                'encryptions': encryptions_7d,
                'encryptions_trend': round(encryption_trend, 1),
                'decryptions': decryptions_7d,
                'decryptions_trend': round(decryption_trend, 1),
                'active_users': active_users,
                'active_users_trend': round(active_trend, 1)
            },
            'top_users': top_users_data,
            'daily_activity': daily_activity
        })
    except Exception as e:
        logging.exception("Analytics error")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
