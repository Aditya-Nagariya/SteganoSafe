
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
