from flask import Blueprint, request, session, jsonify
from flask_login import login_required

# Create blueprint
theme_bp = Blueprint('theme', __name__)

@theme_bp.route('/update_theme_preference', methods=['POST'])
def update_theme_preference():
    """
    Update theme preference in session
    """
    try:
        data = request.get_json()
        if data and 'dark_mode' in data:
            # Update session with new theme preference
            session['dark_mode'] = bool(data['dark_mode'])
            session.permanent = True  # Make session persistent
            return jsonify({'success': True, 'dark_mode': session['dark_mode']})
        else:
            return jsonify({'success': False, 'error': 'Invalid request data'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
