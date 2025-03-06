
"""
Notification handling routes for SteganoSafe application
"""
from flask import Blueprint, jsonify, request, current_app
from flask_login import current_user, login_required
from models import ActivityLog, NotificationModel, db
import datetime

notifications_bp = Blueprint('notifications_bp', __name__)

@notifications_bp.route('/api/notifications/get')
@login_required
def get_notifications():
    """Get the current user's notifications"""
    try:
        # This is a simple example - in a real implementation, you'd have a notifications table
        # For now, we'll use recent activity logs as "notifications" for the current user
        
        # Get up to 10 most recent notifications
        notifications = NotificationModel.query.filter_by(
            user_id=current_user.id
        ).order_by(
            NotificationModel.created_at.desc()
        ).limit(10).all()
        
        # If notifications table doesn't exist yet, create notifications from activity logs
        if not notifications:
            activities = ActivityLog.query.filter_by(
                user_id=current_user.id
            ).order_by(ActivityLog.timestamp.desc()).limit(5).all()
            
            notifications_data = []
            for activity in activities:
                # Determine notification type based on content
                if 'error' in activity.action.lower():
                    ntype = 'danger'
                elif 'warning' in activity.action.lower():
                    ntype = 'warning'
                elif 'encrypted' in activity.action.lower() or 'success' in activity.action.lower():
                    ntype = 'success'
                else:
                    ntype = 'info'
                
                # Calculate time ago
                if activity.timestamp:
                    now = datetime.datetime.now()
                    diff = now - activity.timestamp
                    if diff.days > 0:
                        time_ago = f"{diff.days}d ago"
                    elif diff.seconds >= 3600:
                        time_ago = f"{diff.seconds // 3600}h ago"
                    elif diff.seconds >= 60:
                        time_ago = f"{diff.seconds // 60}m ago"
                    else:
                        time_ago = "Just now"
                else:
                    time_ago = "Unknown"
                
                notifications_data.append({
                    'id': activity.id,
                    'title': 'Activity Update',
                    'message': activity.action,
                    'type': ntype,
                    'time_ago': time_ago,
                    'is_unread': True
                })
        else:
            notifications_data = []
            for notification in notifications:
                # Calculate time ago
                now = datetime.datetime.now()
                diff = now - notification.created_at
                if diff.days > 0:
                    time_ago = f"{diff.days}d ago"
                elif diff.seconds >= 3600:
                    time_ago = f"{diff.seconds // 3600}h ago"
                elif diff.seconds >= 60:
                    time_ago = f"{diff.seconds // 60}m ago"
                else:
                    time_ago = "Just now"
                
                notifications_data.append({
                    'id': notification.id,
                    'title': notification.title,
                    'message': notification.message,
                    'type': notification.notification_type,
                    'time_ago': time_ago,
                    'is_unread': not notification.is_read
                })
        
        # Count unread notifications
        unread_count = len([n for n in notifications_data if n['is_unread']])
        
        return jsonify({
            'success': True,
            'notifications': notifications_data,
            'unread_count': unread_count
        })
        
    except Exception as e:
        current_app.logger.error(f"Error fetching notifications: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'notifications': [],
            'unread_count': 0
        })

@notifications_bp.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all notifications as read"""
    try:
        # Check if we have a notifications table
        if hasattr(db.Model, 'notifications'):
            NotificationModel.query.filter_by(
                user_id=current_user.id, 
                is_read=False
            ).update({'is_read': True})
            db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.error(f"Error marking notifications as read: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
