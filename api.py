"""
API routes for the SteganoSafe application.
"""
from flask import Blueprint, jsonify, request, current_app, g, send_file
from flask_login import current_user, login_required
from models import db, User, StegoImage, ActivityLog
from io import BytesIO
from PIL import Image
from stego import encrypt_message, decrypt_message, encode_message, decode_message
import time
import logging
# Install PyJWT if not already installed: pip install PyJWT
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
api = Blueprint('api', __name__)

# Define available encryption methods
AVAILABLE_ENCRYPTION_METHODS = ['LSB', 'DCT', 'WAVE']

# Add token_required decorator
# Add token_required decorator
def token_required(f):
    """Decorator to require valid JWT token for API routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header or query string
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token and 'token' in request.args:
            token = request.args.get('token')
            
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
            
        try:
            # Decode the token
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
            
        # Add user to kwargs so it can be used in the route
        return f(current_user=current_user, *args, **kwargs)
        
    return decorated

@api.before_request
def before_request():
    """Log request timing and details"""
    g.start_time = time.time()

@api.after_request
def after_request(response):
    """Log API request completion time"""
    if hasattr(g, 'start_time'):
        elapsed = time.time() - g.start_time
        current_app.logger.debug(f"API request to {request.path} took {elapsed:.4f}s")
    return response

@api.route('/status')
def status():
    """API status check endpoint"""
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'authenticated': current_user.is_authenticated
    })

@api.route('/token', methods=['POST'])
def get_token():
    """Get a JWT token with valid credentials"""
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Authentication credentials missing'}), 401
        
    user = User.query.filter_by(username=auth.username).first()
    
    if not user:
        return jsonify({'message': 'Authentication failed'}), 401
        
    if user.check_password(auth.password):
        token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.now(timezone.utc) + timedelta(hours=24)
            }, 
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        
        return jsonify({'token': token})
    
    return jsonify({'message': 'Authentication failed'}), 401

@api.route('/images', methods=['GET'])
@token_required
def get_images(current_user):
    """Get all images for the authenticated user"""
    images = StegoImage.query.filter_by(user_id=current_user.id).all()
    
    result = []
    for image in images:
        result.append({
            'id': image.id,
            'filename': image.filename,
            'original_filename': image.original_filename,
            'timestamp': image.timestamp.isoformat(),
            'download_url': f"/api/images/{image.id}/download?token={request.args.get('token', '')}"
        })
    
    return jsonify({'images': result})

@api.route('/images/<int:image_id>', methods=['GET'])
@token_required
def get_image(current_user, image_id):
    """Get image details"""
    image = StegoImage.query.filter_by(id=image_id, user_id=current_user.id).first()
    
    if not image:
        return jsonify({'message': 'Image not found or access denied'}), 404
    
    return jsonify({
        'id': image.id,
        'filename': image.filename,
        'original_filename': image.original_filename,
        'timestamp': image.timestamp.isoformat(),
        'download_url': f"/api/images/{image.id}/download?token={request.args.get('token', '')}"
    })

@api.route('/images/<int:image_id>/download', methods=['GET'])
@token_required
def download_image(current_user, image_id):
    """Download an image"""
    image = StegoImage.query.filter_by(id=image_id, user_id=current_user.id).first()
    
    if not image:
        return jsonify({'message': 'Image not found or access denied'}), 404
    
    return send_file(
        BytesIO(image.image_data),
        mimetype='image/png',
        as_attachment=True,
        download_name=image.original_filename
    )

@api.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    """API endpoint for encrypting an image"""
    try:
        # Validate request
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image file provided'}), 400
        
        if 'message' not in request.form:
            return jsonify({'success': False, 'error': 'No message provided'}), 400
            
        if 'password' not in request.form:
            return jsonify({'success': False, 'error': 'No encryption password provided'}), 400
        
        # Process inputs
        image_file = request.files['image']
        message = request.form['message']
        password = request.form['password']
        
        # Open and encrypt the image
        img = Image.open(image_file)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        encrypted_message = encrypt_message(message, password)
        encoded_img = encode_message(img, encrypted_message)
        
        # Save to buffer
        img_buffer = BytesIO()
        encoded_img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return jsonify({
            'success': True,
            'message': 'Encryption successful'
        })
        
    except Exception as e:
        logging.exception("API encryption error")
        return jsonify({'success': False, 'error': str(e)}), 500

@api.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    """API endpoint for decrypting an image"""
    try:
        # Validate request
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image file provided'}), 400
            
        if 'password' not in request.form:
            return jsonify({'success': False, 'error': 'No decryption password provided'}), 400
        
        # Process inputs
        image_file = request.files['image']
        password = request.form['password']
        
        # Open and decrypt the image
        img = Image.open(image_file)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        ciphertext = decode_message(img)
        if not ciphertext:
            return jsonify({'success': False, 'error': 'No hidden message found in this image'}), 400
            
        try:
            decrypted_message = decrypt_message(ciphertext, password)
            return jsonify({
                'success': True,
                'message': decrypted_message
            })
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid password'}), 400
            
    except Exception as e:
        logging.exception("API decryption error")
        return jsonify({'success': False, 'error': str(e)}), 500

@api.route('/decrypt_saved_image', methods=['POST'])
@login_required
def decrypt_saved_image():
    """API endpoint to decrypt a saved image"""
    try:
        # Get request parameters
        image_id = request.form.get('image_id')
        password = request.form.get('password')
        method = request.form.get('encryption_method', 'AUTO')
        
        logging.info(f"API decrypt request for image {image_id} using {method}")
        
        if not image_id:
            return jsonify({'success': False, 'message': 'Image ID is required'}), 400
            
        if not password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400
            
        # Get the image
        image = StegoImage.query.filter_by(id=image_id, user_id=current_user.id).first()
        if not image:
            return jsonify({'success': False, 'message': 'Image not found'}), 404
            
        # Open the image
        from io import BytesIO
        img_io = BytesIO(image.image_data)
        img = Image.open(img_io)
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Try direct decoding first (most reliable)
        from stego import direct_lsb_decode
        ciphertext = direct_lsb_decode(img, debug=True)
        
        # If that fails, try the regular decode methods
        if not ciphertext:
            from stego import decode_message
            ciphertext = decode_message(img, method='AUTO', debug=True)
            
        # If we still don't have anything, it's not there
        if not ciphertext:
            return jsonify({'success': False, 'message': 'No hidden message found in image'}), 400
            
        # Try decrypting the message
        try:
            from stego import decrypt_message, decrypt_message_safe
            try:
                decrypted_message = decrypt_message(ciphertext, password, debug=True)
            except Exception:
                # Fall back to safe decryption
                decrypted_message = decrypt_message_safe(ciphertext, password, debug=True)
            
            # Log activity
            activity = ActivityLog(
                user_id=current_user.id,
                action=f"Decrypted image: {image.original_filename}"
            )
            db.session.add(activity)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'decrypted_message': decrypted_message,
                'method_used': 'direct' if method == 'AUTO' else method
            })
        except Exception as e:
            logging.error(f"Decryption error: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to decrypt image. Please check your password.'}), 400
    except Exception as e:
        logging.exception(f"API decrypt error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@api.route('/user/images')
@login_required
def user_images():
    """API endpoint to list user's encrypted images"""
    images = StegoImage.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'success': True,
        'images': [
            {
                'id': img.id,
                'filename': img.original_filename,
                'timestamp': img.timestamp.isoformat(),
                'encryption_type': img.encryption_type
            }
            for img in images
        ]
    })
