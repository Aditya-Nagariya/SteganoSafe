"""
Custom Jinja2 filters for the steganography application.
"""
import base64
import logging

logger = logging.getLogger(__name__)

def register_filters(app):
    """Register all custom filters with the Flask app"""
    logger.info("Custom Jinja2 filters registered successfully")
    app.jinja_env.filters['b64encode'] = b64encode_filter
    app.jinja_env.filters['file_size'] = file_size_filter
    
    # Add date formatting filter
    app.jinja_env.filters['format_date'] = format_date_filter
    
    return app

def b64encode_filter(data):
    """Convert binary data to base64 encoded string for displaying images in HTML"""
    if data is None:
        return ''
    if isinstance(data, str):
        return data
    try:
        # Encode binary data to base64
        encoded = base64.b64encode(data).decode('utf-8')
        return encoded
    except Exception as e:
        logger.error(f"Error encoding data to base64: {str(e)}")
        return ''

def file_size_filter(size_bytes):
    """Format a file size in bytes to a human-readable string"""
    if size_bytes is None:
        return "Unknown"
        
    # Define units and their size in bytes
    units = [
        ('TB', 1024**4),
        ('GB', 1024**3),
        ('MB', 1024**2),
        ('KB', 1024),
        ('B', 1)
    ]
    
    # Find the appropriate unit
    for unit, divisor in units:
        if size_bytes >= divisor:
            size_value = size_bytes / divisor
            if size_value < 10:
                return f"{size_value:.2f} {unit}"
            else:
                return f"{size_value:.1f} {unit}"
                
    return f"{size_bytes} B"

def format_date_filter(date, format="%Y-%m-%d %H:%M"):
    """Format a date using the specified format"""
    if date is None:
        return ''
    try:
        return date.strftime(format)
    except (AttributeError, ValueError) as e:
        logger.error(f"Error formatting date: {str(e)}")
        return str(date)
