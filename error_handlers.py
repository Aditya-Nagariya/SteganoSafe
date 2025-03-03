"""
Custom error handlers for the application.
"""
from flask import render_template, jsonify, request
import traceback
import logging

# Configure logger
logger = logging.getLogger(__name__)

def register_error_handlers(app):
    """Register error handlers with the Flask app"""
    
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'error': 'Forbidden',
                'message': 'You do not have permission to access this resource.'
            }), 403
        return render_template('error.html', 
                              error_code=403, 
                              error_message="Forbidden: You don't have permission to access this resource"), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'error': 'Not Found',
                'message': 'The requested resource was not found.'
            }), 404
        return render_template('error.html', 
                              error_code=404, 
                              error_message="Not Found: The requested resource does not exist"), 404
    
    @app.errorhandler(500)
    def internal_server_error(error):
        logger.error(f"500 error: {str(error)}")
        logger.error(traceback.format_exc())
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'error': 'Internal Server Error',
                'message': 'The server encountered an internal error and was unable to complete your request.'
            }), 500
        return render_template('error.html', 
                              error_code=500, 
                              error_message="Internal Server Error: Something went wrong"), 500
    
    @app.errorhandler(Exception)
    def unhandled_exception(e):
        logger.error(f"Unhandled exception: {str(e)}")
        logger.error(traceback.format_exc())
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'error': 'Server Error',
                'message': f'An unexpected error occurred: {str(e)}'
            }), 500
        return render_template('error.html', 
                              error_code='Error', 
                              error_message=f"An unexpected error occurred: {str(e)}"), 500
