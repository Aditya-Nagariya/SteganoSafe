from flask import Blueprint, request, jsonify, url_for
from flask_login import login_required, current_user
from tasks import encrypt_task

api = Blueprint('api', __name__)

@api.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    try:
        task = encrypt_task.delay(
            request.files['image'].read(),
            request.form['password'],
            request.form['message']
        )
        return jsonify({'success': True, 'task_id': task.id, 'redirect': url_for('dashboard')})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

# ... define additional API endpoints ...
