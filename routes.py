from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from models import db, User, ActivityLog
from forms import RegisterForm
from flask_login import current_user
import re
import logging

auth_bp = Blueprint('auth', __name__)

# New standalone registration route with better error handling
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    
    # For development, make OTP check optional
    if request.method == 'POST':
        logging.debug("Processing registration form")
        
        # For debugging, log all non-password fields
        for field_name, value in request.form.items():
            if 'password' not in field_name.lower():
                logging.debug(f"Form field {field_name}: {value}")
    
    # Validate form
    if form.validate_on_submit():
        try:
            # Check if username already exists
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already taken', 'danger')
                return render_template('register.html', form=form)
            
            # Check if email already exists
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered', 'danger')
                return render_template('register.html', form=form)
            
            # Clean phone number if provided
            phone = form.clean_phone_number()
            
            # Check if phone already exists (if provided)
            if phone and User.query.filter_by(phone_number=phone).first():
                flash('Phone number already registered', 'danger')
                return render_template('register.html', form=form)
            
            # Create new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                phone_number=phone,
                is_verified=True  # Auto-verify in development
            )
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.commit()
            
            # Log activity
            activity = ActivityLog(
                user_id=user.id,
                action="User registered"
            )
            db.session.add(activity)
            db.session.commit()
            
            flash('Registration successful! Please log in', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            logging.exception(f"Registration error: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
    
    elif request.method == 'POST':
        # Log validation errors
        logging.debug(f"Form validation errors: {form.errors}")
        
    return render_template('register.html', form=form)

# Directory structure must be registered in app.py:
# from routes import auth_bp
# app.register_blueprint(auth_bp, url_prefix='/auth')

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models import db, EncryptedImage, ActivityLog  # Fix: Change StegoImage to EncryptedImage
import stego  # Import the stego module
from PIL import Image
import os
import uuid
from io import BytesIO
from werkzeug.utils import secure_filename
import logging
from datetime import datetime
from stego import decode_message, AVAILABLE_ENCRYPTION_METHODS

routes_bp = Blueprint('routes_bp', __name__)
logger = logging.getLogger(__name__)

@routes_bp.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    # Fix to ensure proper encryption
    if request.method == 'POST':
        try:
            # Check if the request has the file part
            if 'image' not in request.files:
                flash('No image selected', 'danger')
                return jsonify({'success': False, 'message': 'No image selected'})
            
            image_file = request.files['image']
            
            # Check if the user submitted an empty form
            if image_file.filename == '':
                flash('No image selected', 'danger')
                return jsonify({'success': False, 'message': 'No image selected'})
            
            message = request.form.get('message', '')
            password = request.form.get('password', '')
            encryption_method = request.form.get('encryption_method', 'LSB')
            
            # Validate inputs
            if not message:
                return jsonify({'success': False, 'message': 'No message provided'})
            
            if not password:
                return jsonify({'success': False, 'message': 'No password provided'})
            
            # Read and validate the image
            try:
                image = Image.open(image_file)
                image = image.convert('RGB')  # Ensure image is in RGB format
            except Exception as e:
                logger.error(f"Error opening image: {str(e)}")
                return jsonify({'success': False, 'message': 'Invalid image file'})
            
            # Apply the selected encryption method
            try:
                # Instead of separate handling for each method, use the unified function
                encoded_image = stego.encode_message_with_method(
                    image, 
                    message, 
                    password, 
                    method=encryption_method, 
                    debug=True
                )
            except ValueError as e:
                logger.error(f"Encryption error: {str(e)}")
                return jsonify({'success': False, 'message': str(e)})
            except Exception as e:
                logger.error(f"Unexpected encryption error: {str(e)}")
                return jsonify({'success': False, 'message': 'An error occurred during encryption'})
            
            # Save the encoded image
            buffer = BytesIO()
            encoded_image.save(buffer, format='PNG')
            buffer.seek(0)
            
            # Generate a unique filename
            filename = f"{uuid.uuid4().hex}.png"
            upload_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
            upload_path = os.path.join(upload_folder, filename)
            
            # Save to filesystem
            try:
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                encoded_image.save(upload_path)
            except Exception as e:
                logger.error(f"Error saving image: {str(e)}")
                return jsonify({'success': False, 'message': 'Error saving encrypted image'})
            
            # Create database record
            try:
                image_data = buffer.getvalue()
                new_image = EncryptedImage(
                    filename=filename,
                    original_filename=secure_filename(image_file.filename),
                    user_id=current_user.id,
                    encryption_type=encryption_method,
                    image_data=image_data
                )
                db.session.add(new_image)
                db.session.commit()
            except Exception as e:
                logger.error(f"Database error: {str(e)}")
                return jsonify({'success': False, 'message': 'Error saving image data'})
            
            flash('Message successfully encrypted and hidden in image!', 'success')
            
            # Return success response
            return jsonify({
                'success': True,
                'message': 'Message successfully encrypted and hidden in image!',
                'redirect': url_for('dashboard'),
                'image_id': new_image.id
            })
            
        except Exception as e:
            logger.error(f"Uncaught exception in encrypt route: {str(e)}")
            return jsonify({'success': False, 'message': f'An unexpected error occurred: {str(e)}'})
    
    # GET request - show encryption form
    encryption_methods = ['LSB', 'PVD', 'DCT', 'DWT']
    return render_template('encrypt.html', encryption_methods=encryption_methods, default_method='LSB')

@routes_bp.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    # Fix to ensure proper decryption
    if request.method == 'POST':
        try:
            # Check if we're decrypting from an uploaded file or a saved image
            image_id = request.form.get('image_id')
            password = request.form.get('password')
            
            if not password:
                return jsonify({'success': False, 'message': 'Password is required'})
            
            # Determine encryption method
            encryption_method = request.form.get('encryption_method', 'AUTO')
            force_direct_lsb = request.form.get('force_direct_lsb') == 'true'
            
            # Log the decryption attempt with method
            logger.info(f"API decrypt request for image {image_id or 'upload'} using {encryption_method}")
            
            # Handle decryption from a saved image
            if image_id:
                # Get image from database
                image_record = EncryptedImage.query.get(image_id)
                if not image_record:
                    return jsonify({'success': False, 'message': 'Image not found'})
                
                # Check if the image belongs to the current user
                if current_user.is_authenticated and image_record.user_id != current_user.id:
                    return jsonify({'success': False, 'message': 'You do not have permission to decrypt this image'})
                
                # Open the image from binary data
                try:
                    image_stream = BytesIO(image_record.image_data)
                    image = Image.open(image_stream)
                except Exception as e:
                    logger.error(f"Error opening image from database: {str(e)}")
                    return jsonify({'success': False, 'message': 'Error loading image'})
                
                # Use the recorded encryption method if available and no override
                if encryption_method == 'AUTO' and image_record.encryption_type and not force_direct_lsb:
                    encryption_method = image_record.encryption_type
                    logger.debug(f"Using recorded encryption method: {encryption_method}")
            else:
                # Check if the request has the file part
                if 'image' not in request.files:
                    return jsonify({'success': False, 'message': 'No image selected'})
                
                image_file = request.files['image']
                
                # Check if the user submitted an empty form
                if image_file.filename == '':
                    return jsonify({'success': False, 'message': 'No image selected'})
                
                # Read and validate the image
                try:
                    image = Image.open(image_file)
                except Exception as e:
                    logger.error(f"Error opening image: {str(e)}")
                    return jsonify({'success': False, 'message': 'Invalid image file'})
            
            # For forced direct LSB, override the method
            if force_direct_lsb:
                encryption_method = 'LSB'
                logger.debug("Forced direct LSB decryption requested")
            
            # Apply the selected decryption method with enhanced error handling
            decrypted_message = None
            last_error = None
            
            # Add more logging for troubleshooting
            logger.debug(f"Using decryption method: {encryption_method}")
            
            # Direct LSB fallback first regardless of method
            # This is the most reliable approach for many steganography images
            try:
                logger.debug("Attempting direct LSB decryption first as primary method")
                from stego import decrypt_lsb
                decrypted_message = decrypt_lsb(image, password)
                if decrypted_message:
                    logger.debug("Direct LSB decryption successful")
                    return jsonify({
                        'success': True,
                        'decrypted_message': decrypted_message
                    })
            except Exception as lsb_e:
                # Only log the error, don't return yet
                logger.debug(f"Direct LSB decryption failed: {str(lsb_e)}")
                last_error = f"LSB: {str(lsb_e)}"
            
            # Continue with the multi-method approach if direct LSB failed
            # ...existing code...
            
        except ValueError as e:
            logger.error(f"Decryption error: {str(e)}")
            return jsonify({'success': False, 'message': str(e)})
        except Exception as e:
            logger.error(f"Unexpected decryption error: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to decrypt message. Please check the password and encryption method.'})
    
    # GET requests should not reach here
    return jsonify({'success': False, 'message': 'Method not allowed'})
