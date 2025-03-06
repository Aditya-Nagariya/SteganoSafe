#!/usr/bin/env python3
"""
Analytics API for the SteganoSafe application.
This module provides enhanced analytics functionality and data processing.
"""
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
import logging
import traceback
import json
from datetime import datetime, timedelta
from sqlalchemy import func, desc, and_, extract
import pandas as pd
import numpy as np
from collections import defaultdict, Counter

# Setup logging
logger = logging.getLogger(__name__)

def init_analytics_api(app, db, User, ActivityLog, StegoImage, admin_required):
    """Initialize the analytics API blueprint and attach it to the app"""
    analytics_api = Blueprint('analytics_api', __name__, url_prefix='/api/v1/analytics')
    
    @analytics_api.route('/summary', methods=['GET'])
    @login_required
    @admin_required
    def get_summary():
        """Get summary analytics data"""
        try:
            # Get time period from query parameters
            days = int(request.args.get('days', '7'))
            
            # Calculate time periods
            now = datetime.now()
            period_start = now - timedelta(days=days)
            prev_period_start = now - timedelta(days=days*2)
            
            # Prepare the summary data
            summary = {
                'time_period': {
                    'days': days,
                    'start_date': period_start.strftime('%Y-%m-%d'),
                    'end_date': now.strftime('%Y-%m-%d')
                },
                'users': get_user_metrics(db, User, period_start, prev_period_start),
                'activities': get_activity_metrics(db, ActivityLog, period_start, prev_period_start),
                'images': get_image_metrics(db, StegoImage, period_start, prev_period_start),
                'system_status': get_system_status(app)
            }
            
            return jsonify({
                'success': True,
                'summary': summary
            })
        except Exception as e:
            logger.error(f"Error in analytics summary: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @analytics_api.route('/users', methods=['GET'])
    @login_required
    @admin_required
    def get_user_analytics():
        """Get detailed user analytics"""
        try:
            # Get time period from query parameters
            days = int(request.args.get('days', '30'))
            now = datetime.now()
            period_start = now - timedelta(days=days)
            
            # Get user registrations over time
            registrations = db.session.query(
                func.date(User.created_at).label('date'),
                func.count().label('count')
            ).filter(User.created_at >= period_start).group_by(func.date(User.created_at)).all()
            
            # Get user activity over time
            user_activity = db.session.query(
                func.date(ActivityLog.timestamp).label('date'),
                func.count(func.distinct(ActivityLog.user_id)).label('count')
            ).filter(ActivityLog.timestamp >= period_start).group_by(func.date(ActivityLog.timestamp)).all()
            
            # Get most active users
            active_users = db.session.query(
                User.id.label('user_id'),
                User.username.label('username'),
                func.count(ActivityLog.id).label('activity_count')
            ).join(ActivityLog, ActivityLog.user_id == User.id)\
             .filter(ActivityLog.timestamp >= period_start)\
             .group_by(User.id)\
             .order_by(desc('activity_count'))\
             .limit(10).all()
            
            # Format results
            result = {
                'registrations': [
                    {'date': str(r.date), 'count': r.count} for r in registrations
                ],
                'user_activity': [
                    {'date': str(a.date), 'active_users': a.count} for a in user_activity
                ],
                'most_active_users': [
                    {
                        'user_id': u.user_id,
                        'username': u.username,
                        'activity_count': u.activity_count
                    } for u in active_users
                ]
            }
            
            return jsonify({
                'success': True,
                'user_analytics': result
            })
        except Exception as e:
            logger.error(f"Error in user analytics: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @analytics_api.route('/activities', methods=['GET'])
    @login_required
    @admin_required
    def get_activity_analytics():
        """Get detailed activity analytics"""
        try:
            # Get time period from query parameters
            days = int(request.args.get('days', '30'))
            now = datetime.now()
            period_start = now - timedelta(days=days)
            
            # Get activity counts by type
            activity_types = db.session.query(
                ActivityLog.action,
                func.count().label('count')
            ).filter(ActivityLog.timestamp >= period_start)\
             .group_by(ActivityLog.action)\
             .order_by(desc('count'))\
             .all()
            
            # Get activity counts by day
            daily_activity = db.session.query(
                func.date(ActivityLog.timestamp).label('date'),
                func.count().label('count')
            ).filter(ActivityLog.timestamp >= period_start)\
             .group_by(func.date(ActivityLog.timestamp))\
             .all()
            
            # Get activity counts by hour of day
            hourly_activity = db.session.query(
                extract('hour', ActivityLog.timestamp).label('hour'),
                func.count().label('count')
            ).filter(ActivityLog.timestamp >= period_start)\
             .group_by(extract('hour', ActivityLog.timestamp))\
             .all()
            
            # Format results
            result = {
                'activity_types': [
                    {'action': a.action, 'count': a.count} for a in activity_types
                ],
                'daily_activity': [
                    {'date': str(d.date), 'count': d.count} for d in daily_activity
                ],
                'hourly_activity': [
                    {'hour': int(h.hour), 'count': h.count} for h in hourly_activity
                ]
            }
            
            # Add missing hours with zero count
            hours_dict = {h['hour']: h['count'] for h in result['hourly_activity']}
            for hour in range(24):
                if hour not in hours_dict:
                    result['hourly_activity'].append({'hour': hour, 'count': 0})
            
            # Sort by hour
            result['hourly_activity'].sort(key=lambda x: x['hour'])
            
            return jsonify({
                'success': True,
                'activity_analytics': result
            })
        except Exception as e:
            logger.error(f"Error in activity analytics: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @analytics_api.route('/images', methods=['GET'])
    @login_required
    @admin_required
    def get_image_analytics():
        """Get detailed image analytics"""
        try:
            # Get image counts by user
            image_counts = db.session.query(
                User.username.label('username'),
                func.count(StegoImage.id).label('count')
            ).join(StegoImage, StegoImage.user_id == User.id)\
             .group_by(User.username)\
             .order_by(desc('count'))\
             .limit(10).all()
            
            # Get image counts by encryption type
            encryption_types = db.session.query(
                StegoImage.encryption_type,
                func.count().label('count')
            ).group_by(StegoImage.encryption_type)\
             .order_by(desc('count'))\
             .all()
            
            # Format results
            result = {
                'image_counts_by_user': [
                    {'username': i.username, 'count': i.count} for i in image_counts
                ],
                'encryption_types': [
                    {'type': e.encryption_type, 'count': e.count} for e in encryption_types
                ]
            }
            
            return jsonify({
                'success': True,
                'image_analytics': result
            })
        except Exception as e:
            logger.error(f"Error in image analytics: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # Helper functions
    def get_user_metrics(db, User, period_start, prev_period_start):
        """Get user metrics for the analytics summary"""
        total_users = User.query.count()
        new_users = User.query.filter(User.created_at >= period_start).count()
        prev_period_users = User.query.filter(
            User.created_at >= prev_period_start,
            User.created_at < period_start
        ).count()
        
        # Calculate trend percentage
        if prev_period_users == 0:
            trend = 100 if new_users > 0 else 0
        else:
            trend = round(((new_users - prev_period_users) / prev_period_users) * 100, 1)
        
        # Get verified users
        verified_users = User.query.filter_by(is_verified=True).count()
        
        # Get new users per day
        daily_signups = db.session.query(
            func.date(User.created_at).label('date'),
            func.count().label('count')
        ).filter(User.created_at >= period_start).group_by(func.date(User.created_at)).all()
        
        return {
            'total': total_users,
            'new': new_users,
            'trend': trend,
            'verified': verified_users,
            'daily_signups': [
                {'date': str(day.date), 'count': day.count} for day in daily_signups
            ]
        }
    
    def get_activity_metrics(db, ActivityLog, period_start, prev_period_start):
        """Get activity metrics for the analytics summary"""
        total_activities = ActivityLog.query.count()
        period_activities = ActivityLog.query.filter(ActivityLog.timestamp >= period_start).count()
        prev_period_activities = ActivityLog.query.filter(
            ActivityLog.timestamp >= prev_period_start,
            ActivityLog.timestamp < period_start
        ).count()
        
        # Calculate trend percentage
        if prev_period_activities == 0:
            trend = 100 if period_activities > 0 else 0
        else:
            trend = round(((period_activities - prev_period_activities) / prev_period_activities) * 100, 1)
        
        # Get encryption/decryption activities
        encryptions = ActivityLog.query.filter(
            ActivityLog.timestamp >= period_start,
            ActivityLog.action.like('%Encrypted%')
        ).count()
        
        decryptions = ActivityLog.query.filter(
            ActivityLog.timestamp >= period_start,
            ActivityLog.action.like('%decrypted%')
        ).count()
        
        # Get activity breakdown
        activity_types = {}
        
        activity_query = db.session.query(
            ActivityLog.action,
            func.count().label('count')
        ).filter(ActivityLog.timestamp >= period_start)\
         .group_by(ActivityLog.action)\
         .all()
         
        for row in activity_query:
            # Extract key parts of the action text
            if 'Encrypted' in row.action:
                activity_types['encryption'] = activity_types.get('encryption', 0) + row.count
            elif 'decrypted' in row.action:
                activity_types['decryption'] = activity_types.get('decryption', 0) + row.count
            elif 'logged in' in row.action:
                activity_types['login'] = activity_types.get('login', 0) + row.count
            elif 'registered' in row.action:
                activity_types['registration'] = activity_types.get('registration', 0) + row.count
            else:
                activity_types['other'] = activity_types.get('other', 0) + row.count
        
        return {
            'total': total_activities,
            'period_total': period_activities,
            'trend': trend,
            'encryptions': encryptions,
            'decryptions': decryptions,
            'breakdown': activity_types
        }
    
    def get_image_metrics(db, StegoImage, period_start, prev_period_start):
        """Get image metrics for the analytics summary"""
        total_images = StegoImage.query.count()
        
        # Count images with created_at field (some might not have it if old records)
        has_created_at = db.session.query(StegoImage.id).filter(StegoImage.created_at.isnot(None)).count()
        
        # Get period counts only if we have created_at data
        if has_created_at > 0:
            period_images = StegoImage.query.filter(StegoImage.created_at >= period_start).count()
            prev_period_images = StegoImage.query.filter(
                StegoImage.created_at >= prev_period_start,
                StegoImage.created_at < period_start
            ).count()
            
            # Calculate trend
            if prev_period_images == 0:
                trend = 100 if period_images > 0 else 0
            else:
                trend = round(((period_images - prev_period_images) / prev_period_images) * 100, 1)
        else:
            period_images = None
            trend = None
        
        # Get encryption types
        encryption_types = db.session.query(
            StegoImage.encryption_type,
            func.count().label('count')
        ).group_by(StegoImage.encryption_type).all()
        
        encryption_breakdown = {row.encryption_type: row.count for row in encryption_types}
        
        return {
            'total': total_images,
            'period_images': period_images,
            'trend': trend,
            'encryption_types': encryption_breakdown
        }
    
    def get_system_status(app):
        """Get system status information"""
        import psutil
        import platform
        
        try:
            # Basic system info
            system_info = {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'flask_version': app.config.get('FLASK_VERSION', 'Unknown'),
            }
            
            # Resources usage
            resources = {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
            }
            
            # Database status
            from models import db
            db_status = {
                'connected': True,
                'tables': [
                    {'name': 'users', 'count': User.query.count()},
                    {'name': 'activity_logs', 'count': ActivityLog.query.count()},
                    {'name': 'stego_images', 'count': StegoImage.query.count()},
                ]
            }
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            system_info = {'error': str(e)}
            resources = {}
            db_status = {'connected': False}
        
        return {
            'system_info': system_info,
            'resources': resources,
            'database': db_status,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    # Register the blueprint with the app
    app.register_blueprint(analytics_api)
    logger.info("Analytics API initialized")
    
    return analytics_api