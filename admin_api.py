"""
Admin API endpoints for the SteganoSafe application.
This module provides the backend API for admin features.
"""
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
from models import db, User, StegoImage, ActivityLog
import logging
import traceback
from datetime import datetime, timedelta
from sqlalchemy import func, desc
import json
import os

# Import the analytics functions
from analytics import (
    parse_logs, 
    generate_user_activity_report, 
    get_hourly_usage_heatmap,
    get_image_analytics,
    export_analytics_data,
    detect_suspicious
)

# Setup logger
logger = logging.getLogger(__name__)

# Create blueprint
admin_api = Blueprint('admin_api', __name__, url_prefix='/admin/api')

# Admin required decorator
def admin_required(view):
    """Decorator to require admin role for API endpoints"""
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({
                'success': False, 
                'message': 'Admin access required'
            }), 403
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped

# API Health check endpoint
@admin_api.route('/health')
@login_required
@admin_required
def api_health():
    """API health check endpoint"""
    return jsonify({
        'success': True,
        'message': 'Admin API is operational',
        'timestamp': datetime.now().isoformat(),
        'user': current_user.username,
        'role': current_user.role
    })

# User management API endpoints
@admin_api.route('/users')
@login_required
@admin_required
def list_users():
    """Get all users"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        # Apply filters if provided
        query = User.query
        
        if 'filter' in request.args:
            filter_term = request.args.get('filter')
            query = query.filter(
                (User.username.like(f'%{filter_term}%')) | 
                (User.email.like(f'%{filter_term}%'))
            )
        
        # Apply sorting
        sort_field = request.args.get('sort', 'id')
        sort_dir = request.args.get('dir', 'asc')
        
        if sort_dir == 'desc':
            query = query.order_by(desc(getattr(User, sort_field)))
        else:
            query = query.order_by(getattr(User, sort_field))
        
        # Paginate results
        users_page = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Format response
        user_list = []
        for user in users_page.items:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'is_verified': user.is_verified,
                'created_at': user.created_at.isoformat() if user.created_at else None
            })
        
        return jsonify({
            'success': True,
            'users': user_list,
            'pagination': {
                'total': users_page.total,
                'pages': users_page.pages,
                'page': page,
                'per_page': per_page,
                'has_next': users_page.has_next,
                'has_prev': users_page.has_prev
            }
        })
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@admin_api.route('/users/<int:user_id>')
@login_required
@admin_required
def get_user(user_id):
    """Get details for a specific user"""
    try:
        user = User.query.get_or_404(user_id)
        
        # Get user activity stats
        image_count = StegoImage.query.filter_by(user_id=user_id).count()
        activity_count = ActivityLog.query.filter_by(user_id=user_id).count()
        
        # Get recent activities
        recent_activities = ActivityLog.query.filter_by(user_id=user_id)\
            .order_by(ActivityLog.timestamp.desc())\
            .limit(10)\
            .all()
        
        activities = []
        for activity in recent_activities:
            activities.append({
                'id': activity.id,
                'action': activity.action,
                'timestamp': activity.timestamp.isoformat() if activity.timestamp else None,
                'ip_address': activity.ip_address
            })
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'phone_number': user.phone_number,
                'is_verified': user.is_verified,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': get_last_login(user.id),
                'stats': {
                    'image_count': image_count,
                    'activity_count': activity_count
                },
                'recent_activities': activities
            }
        })
    except Exception as e:
        logger.error(f"Error getting user details: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

def get_last_login(user_id):
    """Get a user's last login time"""
    last_login = ActivityLog.query\
        .filter_by(user_id=user_id)\
        .filter(ActivityLog.action.like('%logged in%'))\
        .order_by(ActivityLog.timestamp.desc())\
        .first()
        
    return last_login.timestamp.isoformat() if last_login and last_login.timestamp else None

@admin_api.route('/dashboard-stats')
@login_required
@admin_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Calculate time periods
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - timedelta(days=1)
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)
        
        # User stats
        total_users = User.query.count()
        new_users_today = User.query.filter(User.created_at >= today_start).count()
        new_users_week = User.query.filter(User.created_at >= week_start).count()
        verified_users = User.query.filter_by(is_verified=True).count()
        
        # Activity stats
        total_activities = ActivityLog.query.count()
        today_activities = ActivityLog.query.filter(ActivityLog.timestamp >= today_start).count()
        yesterday_activities = ActivityLog.query.filter(
            ActivityLog.timestamp >= yesterday_start,
            ActivityLog.timestamp < today_start
        ).count()
        
        login_activities = ActivityLog.query.filter(ActivityLog.action.like('%logged in%')).count()
        
        # Image stats
        total_images = StegoImage.query.count()
        recent_images = StegoImage.query.filter(StegoImage.created_at >= week_start).count() if hasattr(StegoImage, 'created_at') else None
        
        return jsonify({
            'success': True,
            'stats': {
                'users': {
                    'total': total_users,
                    'new_today': new_users_today,
                    'new_week': new_users_week,
                    'verified': verified_users,
                    'verification_rate': round((verified_users / total_users) * 100, 1) if total_users > 0 else 0
                },
                'activities': {
                    'total': total_activities,
                    'today': today_activities,
                    'yesterday': yesterday_activities,
                    'trend': ((today_activities - yesterday_activities) / yesterday_activities) * 100 if yesterday_activities > 0 else 0,
                    'login_count': login_activities
                },
                'images': {
                    'total': total_images,
                    'recent': recent_images
                },
                'timestamp': now.isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@admin_api.route('/logs/app')
@login_required
@admin_required
def get_app_logs():
    """Get application log data"""
    try:
        max_lines = int(request.args.get('lines', 500))
        log_results = parse_logs(log_file="app.log", max_lines=max_lines)
        
        if log_results.get("success", False):
            return jsonify({
                'success': True,
                'logs': log_results
            })
        else:
            return jsonify({
                'success': False,
                'message': log_results.get('error', 'Unknown error parsing logs')
            }), 500
    except Exception as e:
        logger.error(f"Error getting app logs: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@admin_api.route('/analytics/user-activity')
@login_required
@admin_required
def user_activity_report():
    """Get user activity analytics report"""
    try:
        days = int(request.args.get('days', 30))
        report = generate_user_activity_report(db, User, ActivityLog, days)
        
        if report.get('success', False):
            return jsonify({
                'success': True,
                'data': report
            })
        else:
            return jsonify({
                'success': False,
                'message': report.get('error', 'Error generating report')
            }), 500
    except Exception as e:
        logger.error(f"Error generating user activity report: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@admin_api.route('/analytics/usage-heatmap')
@login_required
@admin_required
def usage_heatmap():
    """Get usage heatmap data"""
    try:
        days = int(request.args.get('days', 30))
        heatmap_data = get_hourly_usage_heatmap(db, ActivityLog, days)
        
        if heatmap_data.get('success', False):
            return jsonify({
                'success': True,
                'data': heatmap_data
            })
        else:
            return jsonify({
                'success': False,
                'message': heatmap_data.get('error', 'Error generating heatmap')
            }), 500
    except Exception as e:
        logger.error(f"Error generating usage heatmap: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@admin_api.route('/analytics/image-stats')
@login_required
@admin_required
def image_statistics():
    """Get image analytics data"""
    try:
        days = int(request.args.get('days', 30))
        image_stats = get_image_analytics(db, User, StegoImage, days)
        
        if image_stats.get('success', False):
            return jsonify({
                'success': True,
                'data': image_stats
            })
        else:
            return jsonify({
                'success': False,
                'message': image_stats.get('error', 'Error retrieving image stats')
            }), 500
    except Exception as e:
        logger.error(f"Error retrieving image statistics: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@admin_api.route('/analytics/export')
@login_required
@admin_required
def export_analytics():
    """Export analytics data in specified format"""
    try:
        format = request.args.get('format', 'json')
        
        if format not in ['json', 'csv']:
            return jsonify({
                'success': False,
                'message': f"Unsupported format: {format}"
            }), 400
            
        export_data = export_analytics_data(db, User, ActivityLog, StegoImage, format)
        
        if export_data.get('success', False):
            return jsonify({
                'success': True,
                'format': export_data.get('format'),
                'data': export_data.get('data')
            })
        else:
            return jsonify({
                'success': False,
                'message': export_data.get('error', 'Error exporting data')
            }), 500
    except Exception as e:
        logger.error(f"Error exporting analytics data: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@admin_api.route('/security/suspicious')
@login_required
@admin_required
def suspicious_activities():
    """Detect suspicious activities"""
    try:
        days = int(request.args.get('days', 7))
        suspicious_data = detect_suspicious(db, User, ActivityLog, days)
        
        if suspicious_data.get('success', False):
            return jsonify({
                'success': True,
                'data': suspicious_data
            })
        else:
            return jsonify({
                'success': False,
                'message': suspicious_data.get('error', 'Error detecting suspicious activities')
            }), 500
    except Exception as e:
        logger.error(f"Error detecting suspicious activities: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

# Register the blueprint with the app
def init_admin_api(app):
    app.register_blueprint(admin_api)
    logger.info("Admin API initialized")
    return admin_api
