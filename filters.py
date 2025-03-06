import base64
import logging

logger = logging.getLogger(__name__)

def register_filters(app):
    """Register custom Jinja2 filters"""
    
    @app.template_filter('b64encode')
    def b64encode_filter(data):
        """Convert binary data to base64 encoded string for displaying images in HTML"""
        if data is None:
            return ''
        
        # If data is already a string, return it
        if isinstance(data, str):
            return data
            
        try:
            # Encode binary data to base64
            encoded = base64.b64encode(data).decode('utf-8')
            return encoded
        except Exception as e:
            logger.error(f"Error encoding data to base64: {str(e)}")
            return ''
            
    # Add more filters here if needed
    
    logger.info("Custom Jinja2 filters registered successfully")
