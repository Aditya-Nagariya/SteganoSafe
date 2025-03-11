"""
API routes for the SteganoSafe application.
"""
from flask import Blueprint, jsonify, request, current_app, g, send_file
from flask_login import current_user, login_required
from models import db, User, StegoImage, ActivityLog
from io import BytesIO
from PIL import Image
from stego import (
    encrypt_message, decrypt_message, encode_message, decode_message,
    decrypt_lsb, decode_message_pvd, decode_message_dct, decode_message_dwt
)
import time
import logging
# Install PyJWT if not already installed: pip install PyJWT
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
import os
import traceback

api = Blueprint('api', __name__)

# Define available encryption methods
AVAILABLE_ENCRYPTION_METHODS = ['LSB', 'DCT', 'WAVE', 'PVD', 'DWT']

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
    """API endpoint to decrypt a saved image with robust method handling"""
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
        from PIL import Image
        
        img_io = BytesIO(image.image_data)
        img = Image.open(img_io)
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Check if this image was created with a specific method
        original_method = image.encryption_type
        
        # If AUTO is selected but we know the original encryption method, use that directly
        if method == 'AUTO' and original_method:
            method = original_method
            logging.debug(f"Using the original encryption method from database: {method}")
        
        # Try the indicated method first (or AUTO logic)
        decrypted_message = None
        message_found = False
        method_used = None
        
        # Try specific method if provided
        if method != 'AUTO':
            try:
                logging.debug(f"Trying {method} method as specified")
                
                # Dispatch to the appropriate method-specific function
                if method == 'LSB':
                    try:
                        decrypted_message = decrypt_lsb(img, password)
                        if decrypted_message:
                            message_found = True
                            method_used = 'LSB'
                    except Exception as e:
                        logging.debug(f"LSB decryption failed: {e}")
                
                elif method == 'PVD':
                    try:
                        # First try with the intended method
                        ciphertext = decode_message_pvd(img, debug=True)
                        
                        if ciphertext:
                            # PVD uses default password, so we don't need to decrypt further
                            decrypted_message = ciphertext
                            message_found = True
                            method_used = 'PVD'
                    except Exception as e:
                        logging.debug(f"PVD decryption failed: {e}")
                
                elif method == 'DCT':
                    try:
                        # First try with the intended method
                        ciphertext = decode_message_dct(img, debug=True)
                        
                        if ciphertext:
                            # DCT uses default password, so we don't need to decrypt further
                            decrypted_message = ciphertext
                            message_found = True
                            method_used = 'DCT'
                    except Exception as e:
                        logging.debug(f"DCT decryption failed: {e}")
                
                elif method == 'DWT':
                    try:
                        # First try with the intended method
                        ciphertext = decode_message_dwt(img, debug=True)
                        
                        if ciphertext:
                            # DWT uses default password, so we don't need to decrypt further
                            decrypted_message = ciphertext
                            message_found = True
                            method_used = 'DWT'
                    except Exception as e:
                        logging.debug(f"DWT decryption failed: {e}")
            except Exception as e:
                logging.debug(f"Method {method} failed: {e}")
        
        # If the specified method failed or AUTO was selected, try all methods
        if not message_found:
            logging.debug("Trying all methods sequentially")
            
            # Try all methods one by one
            methods_to_try = ['LSB', 'PVD', 'DCT', 'DWT']
            
            for current_method in methods_to_try:
                try:
                    logging.debug(f"Trying method: {current_method}")
                    
                    if current_method == 'LSB':
                        try:
                            temp_message = decrypt_lsb(img, password)
                            if temp_message:
                                decrypted_message = temp_message
                                message_found = True
                                method_used = 'LSB'
                                break
                        except Exception as e:
                            logging.debug(f"LSB attempt failed: {e}")
                    
                    elif current_method == 'PVD':
                        try:
                            temp_message = decode_message_pvd(img, debug=True)
                            if temp_message and not isinstance(temp_message, str) and not temp_message.count('m') > len(temp_message) * 0.9:
                                decrypted_message = temp_message
                                message_found = True
                                method_used = 'PVD'
                                break
                        except Exception as e:
                            logging.debug(f"PVD attempt failed: {e}")
                    
                    elif current_method == 'DCT':
                        try:
                            temp_message = decode_message_dct(img, debug=True)
                            if temp_message and not isinstance(temp_message, str) and not temp_message.count('m') > len(temp_message) * 0.9:
                                decrypted_message = temp_message
                                message_found = True
                                method_used = 'DCT'
                                break
                        except Exception as e:
                            logging.debug(f"DCT attempt failed: {e}")
                    
                    elif current_method == 'DWT':
                        try:
                            temp_message = decode_message_dwt(img, debug=True)
                            if temp_message and not isinstance(temp_message, str) and not temp_message.count('m') > len(temp_message) * 0.9:
                                decrypted_message = temp_message
                                message_found = True
                                method_used = 'DWT'
                                break
                        except Exception as e:
                            logging.debug(f"DWT attempt failed: {e}")
                
                except Exception as e:
                    logging.debug(f"Failed attempting method {current_method}: {e}")
        
        # If we found a message, return success
        if message_found and decrypted_message:
            # Log activity
            activity = ActivityLog(
                user_id=current_user.id,
                action=f"Decrypted image: {image.original_filename} ({method_used})"
            )
            db.session.add(activity)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'decrypted_message': decrypted_message,
                'method_used': method_used
            })
        
        # If all else fails
        return jsonify({
            'success': False,
            'message': 'Failed to decrypt image. Please try a different encryption method or check your password.',
            'recovery_available': True
        }), 400
            
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

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import db, EncryptedImage
import stego
from PIL import Image
from io import BytesIO
import logging

api_bp = Blueprint('api_bp', __name__)
logger = logging.getLogger(__name__)

@api_bp.route('/decrypt_fallback', methods=['POST'])
@login_required
def decrypt_fallback():
    """
    Special fallback endpoint that tries all decryption methods with aggressive recovery
    """
    try:
        # Get image ID and password
        image_id = request.form.get('image_id')
        password = request.form.get('password')
        
        if not password:
            return jsonify({'success': False, 'message': 'Password is required'})
            
        if not image_id:
            return jsonify({'success': False, 'message': 'Image ID is required'})
            
        # Get image from database
        image_record = EncryptedImage.query.get(image_id)
        if not image_record:
            return jsonify({'success': False, 'message': 'Image not found'})
            
        # Check if the image belongs to the current user
        if image_record.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'You do not have permission to decrypt this image'})
            
        # Open the image from binary data
        try:
            image_stream = BytesIO(image_record.image_data)
            image = Image.open(image_stream)
        except Exception as e:
            logger.error(f"Error opening image from database: {str(e)}")
            return jsonify({'success': False, 'message': 'Error loading image'})
        
        # Try multiple decryption approaches in sequence
        decrypted_message = None
        last_error = None
        methods_tried = []
        
        # 1. Try direct LSB decryption first (most reliable)
        try:
            logger.debug("Attempting direct LSB decryption")
            methods_tried.append("LSB direct")
            decrypted_message = stego.decrypt_lsb(image, password)
            
            if decrypted_message:
                logger.info("Direct LSB decryption successful")
                # Log successful decryption
                activity = ActivityLog(
                    user_id=current_user.id,
                    action=f"Decrypted image using fallback (direct LSB): {image_record.original_filename}"
                )
                db.session.add(activity)
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'decrypted_message': decrypted_message,
                    'method_used': 'LSB direct'
                })
        except Exception as e:
            last_error = f"LSB direct: {str(e)}"
            logger.debug(f"Direct LSB decryption failed: {e}")
        
        # 2. Try extracting raw LSB data and looking for base64 patterns
        if not decrypted_message:
            try:
                logger.debug("Attempting raw LSB extraction")
                methods_tried.append("LSB raw")
                extracted_data = stego.direct_lsb_decode(image, debug=True)
                
                if extracted_data:
                    try:
                        logger.debug("Attempting to decrypt extracted data")
                        decrypted_message = stego.decrypt_message_safe(extracted_data, password, debug=True, image_obj=image)
                        
                        if decrypted_message:
                            logger.info("Raw LSB extraction and safe decryption successful")
                            # Log successful decryption
                            activity = ActivityLog(
                                user_id=current_user.id,
                                action=f"Decrypted image using fallback (raw LSB): {image_record.original_filename}"
                            )
                            db.session.add(activity)
                            db.session.commit()
                            
                            return jsonify({
                                'success': True,
                                'decrypted_message': decrypted_message,
                                'method_used': 'LSB raw'
                            })
                    except Exception as decrypt_e:
                        last_error = f"LSB raw decrypt: {str(decrypt_e)}"
                        logger.debug(f"Failed to decrypt extracted LSB data: {decrypt_e}")
            except Exception as e:
                last_error = f"LSB raw extract: {str(e)}"
                logger.debug(f"Raw LSB extraction failed: {e}")
        
        # 3. Try PVD decoding
        if not decrypted_message:
            try:
                logger.debug("Attempting PVD decoding")
                methods_tried.append("PVD")
                decoded_data = stego.decode_message_pvd(image, debug=True)
                
                if decoded_data:
                    try:
                        decrypted_message = stego.decrypt_message_safe(decoded_data, password, debug=True, image_obj=image)
                        
                        if decrypted_message:
                            logger.info("PVD decryption successful")
                            # Log successful decryption
                            activity = ActivityLog(
                                user_id=current_user.id,
                                action=f"Decrypted image using fallback (PVD): {image_record.original_filename}"
                            )
                            db.session.add(activity)
                            db.session.commit()
                            
                            return jsonify({
                                'success': True,
                                'decrypted_message': decrypted_message,
                                'method_used': 'PVD'
                            })
                    except Exception as decrypt_e:
                        last_error = f"PVD decrypt: {str(decrypt_e)}"
                        logger.debug(f"Failed to decrypt PVD data: {decrypt_e}")
            except Exception as e:
                last_error = f"PVD decode: {str(e)}"
                logger.debug(f"PVD decoding failed: {e}")
        
        # 4. Try DCT and DWT methods as last resort
        for method in ["DCT", "DWT"]:
            if not decrypted_message:
                try:
                    logger.debug(f"Attempting {method} decoding")
                    methods_tried.append(method)
                    
                    if method == "DCT":
                        decoded_data = stego.decode_message_dct(image, debug=True)
                    else:
                        decoded_data = stego.decode_message_dwt(image, debug=True)
                    
                    if decoded_data:
                        try:
                            decrypted_message = stego.decrypt_message_safe(decoded_data, password, debug=True, image_obj=image)
                            
                            if decrypted_message:
                                logger.info(f"{method} decryption successful")
                                # Log successful decryption
                                activity = ActivityLog(
                                    user_id=current_user.id,
                                    action=f"Decrypted image using fallback ({method}): {image_record.original_filename}"
                                )
                                db.session.add(activity)
                                db.session.commit()
                                
                                return jsonify({
                                    'success': True,
                                    'decrypted_message': decrypted_message,
                                    'method_used': method
                                })
                        except Exception as decrypt_e:
                            last_error = f"{method} decrypt: {str(decrypt_e)}"
                            logger.debug(f"Failed to decrypt {method} data: {decrypt_e}")
                except Exception as e:
                    last_error = f"{method} decode: {str(e)}"
                    logger.debug(f"{method} decoding failed: {e}")
        
        # 5. Last resort - try headerless recovery
        if not decrypted_message:
            try:
                logger.debug("Attempting headerless recovery")
                methods_tried.append("Headerless")
                headerless_data = stego.decode_message_without_header(image, debug=True)
                
                if headerless_data:
                    try:
                        decrypted_message = stego.decrypt_message_safe(headerless_data, password, debug=True, image_obj=image)
                        
                        if decrypted_message:
                            logger.info("Headerless recovery successful")
                            # Log successful decryption
                            activity = ActivityLog(
                                user_id=current_user.id,
                                action=f"Decrypted image using fallback (headerless): {image_record.original_filename}"
                            )
                            db.session.add(activity)
                            db.session.commit()
                            
                            return jsonify({
                                'success': True,
                                'decrypted_message': decrypted_message,
                                'method_used': 'Headerless'
                            })
                    except Exception as decrypt_e:
                        last_error = f"Headerless decrypt: {str(decrypt_e)}"
                        logger.debug(f"Failed to decrypt headerless data: {decrypt_e}")
            except Exception as e:
                last_error = f"Headerless extract: {str(e)}"
                logger.debug(f"Headerless recovery failed: {e}")
        
        # If all methods failed, return error with details
        return jsonify({
            'success': False,
            'message': 'All decryption methods failed',
            'details': {
                'methods_tried': methods_tried,
                'last_error': last_error
            }
        })
        
    except Exception as e:
        logger.error(f"Error in decrypt_fallback: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'An unexpected error occurred during decryption: {str(e)}'
        })
