"""
Extensions and initialization helpers for the SteganoSafe application.

This module contains functions to initialize and register various extensions
and components like analytics APIs with the Flask application.
"""
import logging
from flask import Flask

logger = logging.getLogger(__name__)

def register_analytics_api(app, db, User, ActivityLog, StegoImage, admin_required):
    """Register and initialize the analytics API"""
    try:
        from analytics_api import init_analytics_api
        analytics_api = init_analytics_api(app, db, User, ActivityLog, StegoImage, admin_required)
        logger.info("Analytics API registered successfully")
        return analytics_api
    except ImportError as e:
        logger.warning(f"Could not import analytics_api module: {e}")
        logger.warning("Analytics API will not be available")
        return None
    except Exception as e:
        logger.error(f"Error registering analytics API: {e}")
        return None

def register_admin_api(app):
    """Register and initialize the admin API"""
    try:
        from admin_api import init_admin_api
        admin_api = init_admin_api(app)
        logger.info("Admin API registered successfully")
        return admin_api
    except ImportError as e:
        logger.warning(f"Could not import admin_api module: {e}")
        logger.warning("Admin API will not be available")
        return None
    except Exception as e:
        logger.error(f"Error registering admin API: {e}")
        return None

def configure_analytics_dashboard(app):
    """Configure the analytics dashboard routes and plugins"""
    try:
        from analytics_dashboard import init_dashboard
        dashboard = init_dashboard(app)
        logger.info("Analytics dashboard configured successfully")
        return dashboard
    except ImportError as e:
        logger.warning(f"Could not import analytics_dashboard module: {e}")
        return None
    except Exception as e:
        logger.error(f"Error configuring analytics dashboard: {e}")
        return None

def init_extensions(app):
    """Initialize all extensions"""
    # Import dependencies from app context
    from models import db
    from admin_routes import admin_required
    from models import User, ActivityLog, StegoImage
    
    # Register extensions
    register_analytics_api(app, db, User, ActivityLog, StegoImage, admin_required)
    register_admin_api(app)
    
    logger.info("All extensions initialized")
