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
from models import db, StegoImage, ActivityLog
from stego import encrypt_message, decrypt_message, encode_message, decode_message, get_default_encryption_method
from PIL import Image
import logging
from io import BytesIO
from datetime import datetime
from werkzeug.utils import secure_filename

routes_bp = Blueprint('routes_bp', __name__)
logger = logging.getLogger(__name__)

@routes_bp.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    if request.method == 'GET':
        # Get available encryption methods - using our new utility
        from encryption_utils import get_available_encryption_methods, get_default_encryption_method
        encryption_methods = get_available_encryption_methods()
        default_method = get_default_encryption_method()
        
        # Log for debugging
        logging.debug(f"Rendering encrypt.html with methods: {encryption_methods}, default: {default_method}")
        
        return render_template('encrypt.html', 
                              encryption_methods=encryption_methods,
                              default_method=default_method)
    
    # Handle POST request
    try:
        # Validate inputs
        if 'image' not in request.files:
            return jsonify({'success': False, 'message': 'No image file provided'}), 400
        
        image_file = request.files['image']
        if not image_file or image_file.filename == '':
            return jsonify({'success': False, 'message': 'Empty image file'}), 400
        
        message = request.form.get('message')
        if not message:
            return jsonify({'success': False, 'message': 'No message provided'}), 400
        
        password = request.form.get('password')
        if not password:
            return jsonify({'success': False, 'message': 'No password provided'}), 400
        
        # Get encryption method
        encryption_method = request.form.get('encryption_method', 'LSB')
        # Validate method
        from stego import AVAILABLE_ENCRYPTION_METHODS
        if encryption_method not in AVAILABLE_ENCRYPTION_METHODS:
            encryption_method = 'LSB'  # Default to LSB
        
        # Process the image
        try:
            logger.debug(f"Opening image for encryption with method: {encryption_method}")
            img = Image.open(image_file)
            
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
                logger.debug(f"Converted image to RGB mode")
                
            # Encrypt and encode message with debug=True
            logger.debug("Encrypting message")
            encrypted_message = encrypt_message(message, password, debug=True)
            logger.debug(f"Encoding message into image using {encryption_method} method")
            encoded_img = encode_message(img, encrypted_message, method=encryption_method, debug=True)
            
            # Save to BytesIO
            logger.debug("Saving encoded image")
            img_io = BytesIO()
            encoded_img.save(img_io, format='PNG')
            img_io.seek(0)
            image_data = img_io.getvalue()
            
            # Generate unique filename
            filename = secure_filename(image_file.filename)
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
            
            logger.debug(f"Creating database record for: {unique_filename} with method: {encryption_method}")
            # Create database record
            new_image = StegoImage(
                user_id=current_user.id,
                filename=unique_filename,
                original_filename=image_file.filename,
                image_data=image_data,
                encryption_type=encryption_method
            )
            
            db.session.add(new_image)
            
            # Log activity
            activity = ActivityLog(
                user_id=current_user.id,
                action=f"Encrypted image: {image_file.filename} with {encryption_method}"
            )
            
            db.session.add(activity)
            db.session.commit()
            logger.debug("Database records created successfully")
            
            return jsonify({
                'success': True,
                'message': f'Message encrypted and hidden successfully using {encryption_method}',
                'redirect': url_for('dashboard')
            })
            
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400
        except Exception as e:
            logger.exception(f"Image processing error: {str(e)}")
            return jsonify({'success': False, 'message': f"Error processing image: {str(e)}"}), 400
            
    except Exception as e:
        logger.exception(f"Encryption error: {str(e)}")
        return jsonify({'success': False, 'message': f"An error occurred: {str(e)}"}), 500

@routes_bp.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt():
    if request.method == 'GET':
        # Get available encryption methods
        from stego import AVAILABLE_ENCRYPTION_METHODS
        return render_template('decrypt.html', encryption_methods=AVAILABLE_ENCRYPTION_METHODS)
    
    # Handle POST request
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'message': 'No image provided'}), 400
            
        file = request.files['image']
        if not file or file.filename == '':
            return jsonify({'success': False, 'message': 'Empty image file'}), 400
            
        password = request.form.get('password')
        if not password:
            return jsonify({'success': False, 'message': 'Password required'}), 400
        
        # Get encryption method
        encryption_method = request.form.get('encryption_method', 'LSB')
        # Validate method
        from stego import AVAILABLE_ENCRYPTION_METHODS
        if encryption_method not in AVAILABLE_ENCRYPTION_METHODS:
            encryption_method = 'LSB'  # Default to LSB
            
        # Process the image
        try:
            img = Image.open(file)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Log the method being used
            logger.debug(f"Decoding message using {encryption_method} method")
            ciphertext = decode_message(img, method=encryption_method)
            if not ciphertext:
                return jsonify({'success': False, 'message': 'No hidden message found in this image'}), 400
                
            decrypted_message = decrypt_message(ciphertext, password)
            
            # Log activity
            activity = ActivityLog(
                user_id=current_user.id,
                action=f"Decrypted image: {file.filename} with {encryption_method}"
            )
            db.session.add(activity)
            db.session.commit()
            
            # Return the message directly in the response
            return jsonify({
                'success': True,
                'message': 'Message decrypted successfully',
                'decrypted_message': decrypted_message
            })
            
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400
        except Exception as e:
            logger.exception(f"Decryption error: {str(e)}")
            return jsonify({'success': False, 'message': 'Invalid image or password'}), 400
            
    except Exception as e:
        logger.exception(f"Decrypt route error: {str(e)}")
        return jsonify({'success': False, 'message': f"An error occurred: {str(e)}"}), 500
