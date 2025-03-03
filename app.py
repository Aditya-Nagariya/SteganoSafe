import sys
import os
sys.path.insert(0, os.getcwd())

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from email_validator import validate_email, EmailNotValidError
from werkzeug.utils import secure_filename
from PIL import Image as PilImage
import numpy as np
import logging
import time
import re
import base64
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Email, Regexp, Optional
from flask_cors import CORS
from io import BytesIO
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask_socketio import SocketIO, emit
from flask_mail import Mail

# Import app modules
from config import Config
from stego import encrypt_message, decrypt_message, encode_message, decode_message
from models import db, User, StegoImage, ActivityLog
from email_utils import generate_confirmation_token, confirm_token
from otp_utils import generate_otp, send_otp_to_phone, store_otp, verify_otp
from analytics import parse_logs
from magic_box import detect_suspicious
from debug_utils import debug_form_validation
from tasks import encrypt_task

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.logger.setLevel(logging.DEBUG)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, 
    cors_allowed_origins="*", 
    cors_allowed_headers=["Content-Type", "Authorization"],
    logger=True, 
    engineio_logger=True
)
mail = Mail(app)

# Import blueprints
from api import api
from admin_routes import admin_bp

# Register blueprints
app.register_blueprint(api, url_prefix='/api')
app.register_blueprint(admin_bp, url_prefix='/admin')

# Configure login manager
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Create upload directory
with app.app_context():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Form classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address.")
    ])
    
    # Make phone number entirely optional with more permissive validation
    phone_number = StringField('Phone Number', validators=[
        Optional()  # No regex validation since it's causing issues
    ])
    
    # OTP field - validation will be set in the route
    otp = StringField('OTP', validators=[Optional()])  # Make OTP optional
    
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match.")
    ])
    
    submit = SubmitField('Register')
    
    def validate_email(self, field):
        """Validate email format using email_validator but skip domain verification"""
        try:
            validate_email(field.data, check_deliverability=False)
        except EmailNotValidError as e:
            raise ValidationError(str(e))

# User loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            username = form.username.data.strip()
            password = form.password.data
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                login_user(user, remember=form.remember.data)
                
                # Log activity
                activity = ActivityLog(user_id=user.id, action="User logged in")
                db.session.add(activity)
                db.session.commit()
                
                # Check if default admin credentials
                if user.username == 'admin' and user.role == 'admin' and password == 'admin123':
                    flash('You are using default admin credentials. Please change your password!', 'warning')
                    
                # Handle AJAX requests differently
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({
                        'success': True,
                        'redirect': url_for('dashboard')
                    })
                else:
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('dashboard'))
            else:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({
                        'success': False,
                        'message': 'Invalid username or password'
                    }), 401
                else:
                    flash('Invalid username or password', 'danger')
        except Exception as e:
            app.logger.exception(f"Login error: {str(e)}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'message': 'An error occurred during login. Please try again.'
                }), 500
            else:
                flash(f'Login error: {str(e)}', 'danger')
    
    # If it's an AJAX request but validation failed
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': False,
            'message': 'Invalid form data',
            'errors': form.errors
        }), 400
        
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    
    # Debug logging
    app.logger.debug(f"Request method: {request.method}")
    if request.method == 'POST':
        app.logger.debug("Form data received:")
        for key, value in request.form.items():
            if 'password' not in key.lower():
                app.logger.debug(f"  {key}: {value}")
    
    # In development, always force the form validation to succeed
    if app.debug:
        form.phone_number.validators = [Optional()]
        form.otp.validators = []
    
    # Check if this is an AJAX request
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Form validation
    if form.validate_on_submit():
        try:
            # Add more debugging for AJAX request
            if is_ajax:
                app.logger.debug("AJAX request received for registration")
                app.logger.debug(f"CSRF Token: {request.headers.get('X-CSRFToken')}")
            
            # Check for existing users
            if User.query.filter_by(username=form.username.data).first():
                if is_ajax:
                    app.logger.debug("Username already exists")
                    return jsonify({'success': False, 'message': 'Username already taken'}), 400
                flash("Username already taken", "danger")
                return render_template('register.html', form=form)
            
            # Fix the syntax error - email should be a keyword parameter, not a function call
            if User.query.filter_by(email=form.email.data).first():
                if is_ajax:
                    return jsonify({'success': False, 'message': 'Email already registered'}), 400
                flash("Email already registered", "danger")
                return render_template('register.html', form=form)
            
            # Process phone number if provided
            phone = None
            if form.phone_number.data and form.phone_number.data.strip():
                phone = form.phone_number.data.strip()
                # Clean phone number
                phone = re.sub(r'[\s\-\(\)]', '', phone)
                if not phone.startswith('+'):
                    phone = '+' + phone
                    
                # Check if phone already exists
                if User.query.filter_by(phone_number=phone).first():
                    if is_ajax:
                        return jsonify({'success': False, 'message': 'Phone number already registered'}), 400
                    flash("Phone number already registered", "danger")
                    return render_template('register.html', form=form)
            
            # In development mode, skip OTP validation
            if not app.debug:
                # Only validate OTP if we're not in debug mode
                if phone and form.otp.data:
                    if not verify_otp(phone, form.otp.data):
                        if is_ajax:
                            return jsonify({'success': False, 'message': 'Invalid OTP code'}), 400
                        flash("Invalid OTP code", "danger")
                        return render_template('register.html', form=form)
            
            # Create user
            user = User(
                username=form.username.data,
                email=form.email.data,
                phone_number=phone,
                is_verified=True,  # Auto-verify in development
                role='user'
            )
            
            user.set_password(form.password.data)
            
            # Save to database
            db.session.add(user)
            db.session.commit()
            
            # Log activity
            activity = ActivityLog(user_id=user.id, action="User registered")
            db.session.add(activity)
            db.session.commit()
            
            # Success response
            if is_ajax:
                app.logger.debug("User registered successfully via AJAX")
                return jsonify({
                    'success': True,
                    'message': 'Registration successful! Please log in.',
                    'redirect': url_for('login')
                })
            
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.exception(f"Registration error: {str(e)}")
            
            if is_ajax:
                app.logger.debug(f"Exception during AJAX registration: {str(e)}")
                return jsonify({'success': False, 'message': f"Registration error: {str(e)}"}), 500
            
            flash(f"Registration failed: {str(e)}", "danger")
    else:
        if request.method == 'POST':
            app.logger.debug(f"Form validation failed. Errors: {form.errors}")
            if is_ajax:
                app.logger.debug("Returning validation errors via AJAX")
                return jsonify({
                    'success': False, 
                    'message': 'Please correct the errors in your form',
                    'errors': form.errors
                }), 400
            
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", "danger")
    
    return render_template('register.html', form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    app.logger.info(f"Confirm token received: {token}")
    email = confirm_token(token)
    
    if not email:
        flash("The confirmation link is invalid or has expired.", "danger")
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first_or_404()
    
    if user.is_verified:
        flash("Account already verified. Please log in.", "success")
    else:
        user.is_verified = True
        db.session.commit()
        flash("You have confirmed your account. Thanks!", "success")
        
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    images = StegoImage.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', images=images)

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    if request.method == 'GET':
        return render_template('encrypt.html')
    
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
        
        # Process the image
        try:
            img = PilImage.open(image_file)
            
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            # Encrypt and encode message
            encrypted_message = encrypt_message(message, password)
            encoded_img = encode_message(img, encrypted_message)
            
            # Save to BytesIO
            img_io = BytesIO()
            encoded_img.save(img_io, format='PNG')
            img_io.seek(0)
            image_data = img_io.getvalue()
            
            # Generate unique filename
            filename = secure_filename(image_file.filename)
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
            
            # Create database record
            new_image = StegoImage(
                user_id=current_user.id,
                filename=unique_filename,
                original_filename=image_file.filename,
                image_data=image_data,
                encryption_type='LSB'
            )
            
            db.session.add(new_image)
            
            # Log activity
            activity = ActivityLog(
                user_id=current_user.id,
                action=f"Encrypted image: {image_file.filename}"
            )
            
            db.session.add(activity)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Message encrypted and hidden successfully',
                'redirect': url_for('dashboard')
            })
            
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400
        except Exception as e:
            app.logger.exception(f"Image processing error: {str(e)}")
            return jsonify({'success': False, 'message': f"Error processing image: {str(e)}"}), 400
            
    except Exception as e:
        app.logger.exception(f"Encryption error: {str(e)}")
        return jsonify({'success': False, 'message': f"An error occurred: {str(e)}"}), 500

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt():
    if request.method == 'GET':
        return render_template('decrypt.html')
    
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
            
        # Process the image
        try:
            img = PilImage.open(file)
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            ciphertext = decode_message(img)
            if not ciphertext:
                return jsonify({'success': False, 'message': 'No hidden message found in this image'}), 400
                
            decrypted_message = decrypt_message(ciphertext, password)
            return jsonify({
                'success': True,
                'message': 'Message decrypted successfully',
                'redirect': url_for('result', message=decrypted_message)
            })
            
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400
        except Exception as e:
            app.logger.exception(f"Decryption error: {str(e)}")
            return jsonify({'success': False, 'message': 'Invalid image or password'}), 400
            
    except Exception as e:
        app.logger.exception(f"Decrypt route error: {str(e)}")
        return jsonify({'success': False, 'message': f"An error occurred: {str(e)}"}), 500

@app.route('/result')
@login_required
def result():
    decrypted_text = request.args.get('message', '')
    return render_template('result.html', decrypted_text=decrypted_text)

@app.route('/download/<path:filename>')
@login_required
def download_image(filename):
    image = StegoImage.query.filter_by(filename=filename, user_id=current_user.id).first()
    
    if not image:
        abort(404)
    
    return send_file(
        BytesIO(image.image_data),
        mimetype='image/png',
        as_attachment=True,
        download_name=image.original_filename
    )

@app.route('/request_otp', methods=['POST'])
def request_otp():
    phone = request.form.get('phone')
    
    if not phone:
        app.logger.error("Phone number is required")
        return jsonify({'success': False, 'message': 'Phone number required'}), 400
    
    # Clean and validate phone number
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    if not clean_phone.startswith('+'):
        clean_phone = '+' + clean_phone
    
    try:
        # In development mode, always use 123456
        if app.debug:
            otp = '123456'
            app.logger.info(f"DEV MODE - OTP for {clean_phone}: {otp}")
        else:
            otp = generate_otp()
        
        store_otp(clean_phone, otp, expiry=300)  # 5 minutes
        
        # In development mode, just log it
        if not app.debug:
            send_otp_to_phone(clean_phone, otp)
            
        return jsonify({'success': True, 'message': 'OTP sent to your phone'})
    except Exception as e:
        app.logger.exception(f"Error sending OTP: {str(e)}")
        return jsonify({'success': False, 'message': f"Error: {str(e)}"}), 500

@app.route('/verify_otp', methods=['POST'])
def verify_otp_endpoint():
    phone = request.form.get('phone')
    otp_input = request.form.get('otp')
    
    if not phone or not otp_input:
        return jsonify({'success': False, 'message': 'Phone and OTP required'}), 400
    
    # Clean phone number
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    if not clean_phone.startswith('+'):
        clean_phone = '+' + clean_phone
    
    # In development mode, any OTP of "123456" is valid
    if app.debug and otp_input == '123456':
        return jsonify({'success': True, 'message': 'OTP verified successfully'})
    
    if verify_otp(clean_phone, otp_input):
        return jsonify({'success': True, 'message': 'OTP verified successfully'})
    else:
        return jsonify({'success': False, 'message': 'Invalid or expired OTP'}), 400

@app.route('/login_phone', methods=['POST'])
def login_phone():
    phone = request.form.get('phone')
    otp_input = request.form.get('otp')
    
    if not phone or not otp_input:
        return jsonify({'success': False, 'message': 'Phone and OTP required'}), 400
    
    # Clean phone number
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    if not clean_phone.startswith('+'):
        clean_phone = '+' + clean_phone
    
    # In development mode, accept "123456" as OTP
    is_valid_otp = verify_otp(clean_phone, otp_input) or (app.debug and otp_input == '123456')
    
    if is_valid_otp:
        user = User.query.filter_by(phone_number=clean_phone).first()
        if not user:
            return jsonify({
                'success': False,
                'message': 'No user found with this phone number'
            }), 404
        
        login_user(user, remember=True)
        
        # Log activity
        activity = ActivityLog(user_id=user.id, action="User logged in via phone")
        db.session.add(activity)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'redirect': url_for('dashboard')
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid or expired OTP'}), 400

@app.route('/debug/form', methods=['POST'])
def debug_form():
    """Debug endpoint to inspect form data"""
    if not app.debug:
        return jsonify({'error': 'Only available in debug mode'}), 403
    
    data = {
        'form_data': dict(request.form),
        'files': [f.filename for f in request.files.values()],
        'headers': dict(request.headers),
    }
    
    # Don't expose passwords
    if 'password' in data['form_data']:
        data['form_data']['password'] = '[MASKED]'
    if 'confirm_password' in data['form_data']:
        data['form_data']['confirm_password'] = '[MASKED]'
    
    return jsonify(data)

# Create default admin user
def create_default_admin():
    try:
        admin_exists = User.query.filter_by(role='admin').first()
        
        if not admin_exists:
            admin = User(
                username='admin',
                email='admin@example.com',
                phone_number='+1234567890',
                is_verified=True,
                role='admin'
            )
            admin.set_password('admin123')
            
            db.session.add(admin)
            db.session.commit()
            
            app.logger.info('Default admin user created')
            print("\n" + "*" * 80)
            print("* DEFAULT ADMIN CREATED:")
            print("* Username: admin")
            print("* Password: admin123")
            print("*" * 80 + "\n")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error creating default admin: {str(e)}')

# CSRF protection for AJAX requests
@app.after_request
def add_csrf_header(response):
    response.headers.set('X-CSRFToken', generate_csrf())
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    
    # Use environment variable PORT if available (for Render.com), otherwise use 8080
    port = int(os.environ.get('PORT', 8080))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)