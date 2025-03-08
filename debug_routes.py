from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required

debug_routes = Blueprint('debug_routes', __name__)

@debug_routes.route('/debug/decrypt-test', methods=['GET'])
@login_required
def decrypt_test():
    """Test endpoint to verify decrypt response handling"""
    return jsonify({
        'success': True,
        'decrypted_message': 'This is a test decrypted message',
        'message': 'Test successful'
    })

def init_debug_routes(app):
    if app.debug:
        app.register_blueprint(debug_routes)
    
    @app.route('/debug/analytics')
    @login_required
    def debug_analytics_api():
        """Debug endpoint to test the analytics API"""
        from admin_routes import analytics_summary
        try:
            # Call the analytics_summary function directly
            response = analytics_summary()
            # Convert the response to a dictionary
            if isinstance(response, tuple):
                return jsonify({
                    'success': False,
                    'status_code': response[1],
                    'response': str(response[0].get_data(as_text=True))
                })
            return jsonify({
                'success': True,
                'response': str(response.get_data(as_text=True))
            })
        except Exception as e:
            import traceback
            return jsonify({
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            })
