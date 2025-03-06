#!/usr/bin/env python3
"""
Analytics module for SteganoSafe application.
Provides functions for analyzing data, parsing logs, and generating insights.
"""

import os
import re
import json
import datetime
from collections import Counter, defaultdict
import logging
from flask import current_app

# Configure logger
logger = logging.getLogger(__name__)

# Try to import optional dependencies with graceful fallbacks
try:
    import pandas as pd
    import numpy as np
    from sqlalchemy import func, desc
    ANALYTICS_IMPORTS_SUCCESSFUL = True
except ImportError as e:
    logger.warning(f"Analytics dependencies not available: {e}")
    logger.warning("Some analytics features will be disabled.")
    logger.warning("Run setup_analytics.py to install required packages.")
    ANALYTICS_IMPORTS_SUCCESSFUL = False
    
    # Create placeholder np module if it's not available
    class NumpyPlaceholder:
        def std(self, x):
            # Simple standard deviation calculation if numpy is not available
            if not x:
                return 0
            mean = sum(x) / len(x)
            variance = sum((i - mean) ** 2 for i in x) / len(x)
            return variance ** 0.5
    
    np = NumpyPlaceholder()

def check_analytics_available():
    """Check if analytics dependencies are available"""
    return ANALYTICS_IMPORTS_SUCCESSFUL

def parse_logs(log_file="app.log", max_lines=1000):
    """Parse application logs for analytics"""
    if not os.path.exists(log_file):
        return {"error": "Log file not found"}
    
    try:
        # Read log file - limit to last max_lines
        with open(log_file, 'r') as f:
            log_lines = f.readlines()[-max_lines:]
        
        # Parse log entries
        entries = []
        log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (\w+) - (.*)'
        for line in log_lines:
            match = re.match(log_pattern, line)
            if match:
                timestamp, logger_name, level, message = match.groups()
                entries.append({
                    "timestamp": timestamp,
                    "logger": logger_name,
                    "level": level,
                    "message": message
                })
        
        # Generate basic stats
        stats = {
            "total_entries": len(entries),
            "error_count": sum(1 for e in entries if e["level"] == "ERROR"),
            "warning_count": sum(1 for e in entries if e["level"] == "WARNING"),
            "loggers": Counter(e["logger"] for e in entries),
            "levels": Counter(e["level"] for e in entries),
        }
        
        # Look for error patterns
        errors = [e for e in entries if e["level"] == "ERROR"]
        error_patterns = []
        for error in errors:
            # Extract key information from error messages
            if "database" in error["message"].lower():
                error_patterns.append("database_error")
            elif "timeout" in error["message"].lower():
                error_patterns.append("timeout_error")
            elif "permission" in error["message"].lower():
                error_patterns.append("permission_error")
            else:
                error_patterns.append("other_error")
        
        stats["error_patterns"] = Counter(error_patterns)
        
        return {
            "success": True, 
            "stats": stats,
            "recent_errors": errors[-10:] if errors else []
        }
        
    except Exception as e:
        logger.error(f"Error parsing logs: {str(e)}")
        return {
            "success": False, 
            "error": str(e)
        }

# The rest of the functions should check for dependency availability
def generate_user_activity_report(db, User, ActivityLog, days=30):
    """Generate a report on user activity"""
    if not ANALYTICS_IMPORTS_SUCCESSFUL:
        return {
            'success': False,
            'error': 'Analytics dependencies not available. Run setup_analytics.py to install.'
        }
    
    try:
        # Period calculation
        now = datetime.datetime.now()
        period_start = now - datetime.timedelta(days=days)
        
        # User registration stats
        total_users = User.query.count()
        
        new_users = db.session.query(
            func.date(User.created_at).label('date'),
            func.count().label('count')
        ).filter(User.created_at >= period_start)\
         .group_by(func.date(User.created_at))\
         .all()
        
        new_users_data = {
            'dates': [str(row.date) for row in new_users],
            'counts': [row.count for row in new_users]
        }
        
        # Activity stats
        user_activities = db.session.query(
            User.username,
            func.count(ActivityLog.id).label('activity_count')
        ).join(ActivityLog, User.id == ActivityLog.user_id)\
         .filter(ActivityLog.timestamp >= period_start)\
         .group_by(User.username)\
         .order_by(desc('activity_count'))\
         .limit(10)\
         .all()
         
        activity_data = {
            'usernames': [row.username for row in user_activities],
            'counts': [row.activity_count for row in user_activities]
        }
        
        # Daily activity pattern
        daily_activity = db.session.query(
            func.date(ActivityLog.timestamp).label('date'),
            func.count().label('count')
        ).filter(ActivityLog.timestamp >= period_start)\
         .group_by(func.date(ActivityLog.timestamp))\
         .all()
         
        daily_data = {
            'dates': [str(row.date) for row in daily_activity],
            'counts': [row.count for row in daily_activity]
        }
        
        return {
            'success': True,
            'total_users': total_users,
            'new_users': new_users_data,
            'top_users_activity': activity_data,
            'daily_activity': daily_data
        }
        
    except Exception as e:
        logger.error(f"Error generating user activity report: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

# Only include function signatures for the remaining functions to avoid repeating code
def get_hourly_usage_heatmap(db, ActivityLog, days=30):
    """Generate hourly usage data for a heatmap visualization"""
    if not ANALYTICS_IMPORTS_SUCCESSFUL:
        return {
            'success': False,
            'error': 'Analytics dependencies not available. Run setup_analytics.py to install.'
        }
    
    try:
        # Calculate period
        now = datetime.datetime.now()
        period_start = now - datetime.timedelta(days=days)
        
        # Query hourly activity by day of week
        hourly_data = db.session.query(
            func.extract('dow', ActivityLog.timestamp).label('dow'),
            func.extract('hour', ActivityLog.timestamp).label('hour'),
            func.count().label('count')
        ).filter(ActivityLog.timestamp >= period_start)\
         .group_by('dow', 'hour')\
         .order_by('dow', 'hour')\
         .all()
         
        # Initialize data structure for heatmap
        days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        hours = list(range(24))
        
        # Create an empty matrix
        heatmap = np.zeros((7, 24))
        
        # Fill the matrix with data
        for item in hourly_data:
            day_idx = int(item.dow)
            hour_idx = int(item.hour)
            # Ensure indices are valid
            if 0 <= day_idx <= 6 and 0 <= hour_idx <= 23:
                heatmap[day_idx][hour_idx] = item.count
        
        # Format for JSON
        formatted_data = []
        for day_idx, day_name in enumerate(days):
            for hour_idx in range(24):
                formatted_data.append({
                    'day': day_name,
                    'hour': hour_idx,
                    'value': int(heatmap[day_idx][hour_idx])
                })
        
        return {
            'success': True,
            'heatmap_data': formatted_data,
            'days': days,
            'hours': hours
        }
        
    except Exception as e:
        logger.error(f"Error generating usage heatmap: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def get_image_analytics(db, User, StegoImage, days=30):
    """Get analytics for image usage"""
    if not ANALYTICS_IMPORTS_SUCCESSFUL:
        return {
            'success': False,
            'error': 'Analytics dependencies not available. Run setup_analytics.py to install.'
        }
    
    try:
        # Calculate period
        now = datetime.datetime.now()
        period_start = now - datetime.timedelta(days=days)
        
        # Total images
        total_images = StegoImage.query.count()
        
        # Images with created_at data
        has_timestamp = db.session.query(StegoImage.id).filter(StegoImage.created_at.isnot(None)).count()
        
        # Recent images
        if has_timestamp > 0:
            recent_images = StegoImage.query.filter(StegoImage.created_at >= period_start).count()
        else:
            recent_images = None
        
        # Images by encryption type
        encryption_types = db.session.query(
            StegoImage.encryption_type,
            func.count().label('count')
        ).group_by(StegoImage.encryption_type).all()
        
        # Images by user
        images_by_user = db.session.query(
            User.username,
            func.count(StegoImage.id).label('count')
        ).join(StegoImage, User.id == StegoImage.user_id)\
         .group_by(User.username)\
         .order_by(desc('count'))\
         .limit(10).all()
         
        return {
            'success': True,
            'total_images': total_images,
            'recent_images': recent_images,
            'encryption_types': {row.encryption_type: row.count for row in encryption_types},
            'images_by_user': {row.username: row.count for row in images_by_user}
        }
        
    except Exception as e:
        logger.error(f"Error getting image analytics: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def export_analytics_data(db, User, ActivityLog, StegoImage, format='json'):
    """Export analytics data in specified format"""
    if not ANALYTICS_IMPORTS_SUCCESSFUL and format == 'csv':
        return {
            'success': False,
            'error': 'CSV export requires pandas. Run setup_analytics.py to install.'
        }
    
    try:
        # Calculate dates for reports
        now = datetime.datetime.now()
        last_week = now - datetime.timedelta(days=7)
        last_month = now - datetime.timedelta(days=30)
        
        # User metrics
        user_metrics = {
            'total_users': User.query.count(),
            'verified_users': User.query.filter_by(is_verified=True).count(),
            'admin_users': User.query.filter_by(role='admin').count(),
            'new_users_week': User.query.filter(User.created_at >= last_week).count(),
            'new_users_month': User.query.filter(User.created_at >= last_month).count()
        }
        
        # Activity metrics
        activity_metrics = {
            'total_activities': ActivityLog.query.count(),
            'activities_week': ActivityLog.query.filter(ActivityLog.timestamp >= last_week).count(),
            'activities_month': ActivityLog.query.filter(ActivityLog.timestamp >= last_month).count(),
            'encryptions': ActivityLog.query.filter(ActivityLog.action.like('%Encrypted%')).count(),
            'decryptions': ActivityLog.query.filter(ActivityLog.action.like('%decrypted%')).count()
        }
        
        # Image metrics
        image_metrics = {
            'total_images': StegoImage.query.count()
        }
        
        # Compile the report
        report = {
            'generated_at': now.strftime('%Y-%m-%d %H:%M:%S'),
            'users': user_metrics,
            'activities': activity_metrics,
            'images': image_metrics
        }
        
        if format.lower() == 'json':
            return {
                'success': True,
                'format': 'json',
                'data': report
            }
        elif format.lower() == 'csv':
            # Convert to CSV-friendly format
            csv_data = {}
            
            # Flatten nested dictionaries
            for category, metrics in report.items():
                if category == 'generated_at':
                    csv_data['generated_at'] = report['generated_at']
                else:
                    for key, value in metrics.items():
                        csv_data[f"{category}_{key}"] = value
            
            return {
                'success': True,
                'format': 'csv',
                'data': csv_data
            }
        else:
            return {
                'success': False,
                'error': f"Unsupported format: {format}"
            }
            
    except Exception as e:
        logger.error(f"Error exporting analytics data: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def detect_suspicious(db, User, ActivityLog, days=7):
    """Detect suspicious activity patterns"""
    if not ANALYTICS_IMPORTS_SUCCESSFUL:
        return {
            'success': False,
            'error': 'Analytics dependencies not available. Run setup_analytics.py to install.'
        }
    
    try:
        # Calculate time periods
        now = datetime.datetime.now()
        period_start = now - datetime.timedelta(days=7)
        
        # Look for rapid-fire login attempts (possible brute force)
        # Group activities by IP address and look for multiple login attempts in short periods
        suspicious_ips = []
        
        # This approach requires SQLAlchemy window functions which may not be available
        # For simplicity, we'll load the data and process it in Python
        login_activities = ActivityLog.query.filter(
            ActivityLog.timestamp >= period_start,
            ActivityLog.action.like('%logged in%')
        ).order_by(ActivityLog.timestamp).all()
        
        # Group by IP address
        ip_activities = defaultdict(list)
        for activity in login_activities:
            if activity.ip_address:
                ip_activities[activity.ip_address].append(activity)
        
        # Look for suspicious patterns
        for ip, activities in ip_activities.items():
            if len(activities) >= 5:  # Arbitrary threshold
                # Check if multiple attempts happened in a short timeframe
                for i in range(len(activities) - 5):
                    time_diff = activities[i+4].timestamp - activities[i].timestamp
                    if time_diff.total_seconds() < 300:  # 5 minutes
                        suspicious_ips.append({
                            'ip_address': ip,
                            'attempts': len(activities),
                            'timeframe_seconds': time_diff.total_seconds(),
                            'first_attempt': str(activities[i].timestamp),
                            'last_attempt': str(activities[i+4].timestamp)
                        })
                        break  # Only report once per IP
        
        # Look for users with excessive encryption/decryption actions
        suspicious_users = []
        
        # Get activity counts by user
        user_activity_counts = db.session.query(
            User.id,
            User.username,
            func.count().label('count')
        ).join(ActivityLog, User.id == ActivityLog.user_id)\
         .filter(ActivityLog.timestamp >= period_start)\
         .group_by(User.id)\
         .all()
         
        # Calculate average + standard deviation
        counts = [row.count for row in user_activity_counts]
        if counts:
            avg_count = sum(counts) / len(counts)
            std_dev = np.std(counts) if len(counts) > 1 else 0
            
            # Flag users with activity counts > avg + 2*std_dev
            threshold = avg_count + 2 * std_dev
            for row in user_activity_counts:
                if row.count > threshold:
                    suspicious_users.append({
                        'user_id': row.id,
                        'username': row.username,
                        'activity_count': row.count,
                        'avg_activity': avg_count,
                        'threshold': threshold
                    })
        
        return {
            'success': True,
            'suspicious_ips': suspicious_ips,
            'suspicious_users': suspicious_users
        }
        
    except Exception as e:
        logger.error(f"Error detecting suspicious activities: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

# Main entrypoint for manually running analytics
if __name__ == "__main__":
    import sys
    
    if not ANALYTICS_IMPORTS_SUCCESSFUL:
        print("WARNING: Analytics dependencies not available.")
        print("Some features may not work correctly.")
        print("Run setup_analytics.py to install required packages.")
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = "app.log"
        
    print(f"Analyzing log file: {log_file}")
    results = parse_logs(log_file)
    
    if results.get("success", False):
        print(json.dumps(results["stats"], indent=2))
    else:
        print(f"Error: {results.get('error', 'Unknown error')}")