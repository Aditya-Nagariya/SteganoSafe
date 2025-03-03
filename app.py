import sys
import os
import logging
import traceback
from contextlib import suppress

# Configure logging first
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

sys.path.insert(0, os.getcwd())

# Run ensure_db.py to set up database
try:
    from ensure_db import ensure_database
    data_dir, db_path = ensure_database()
    logger.info(f"Database ensured at: {db_path}")
    
    # Update environment with database path
    os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'
    logger.info(f"Set DATABASE_URL to {os.environ['DATABASE_URL']}")
except Exception as e:
    logger.error(f"Database initialization error: {str(e)}")
    logger.error(traceback.format_exc())

# Continue with regular imports
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

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.logger.setLevel(logging.DEBUG)

# Import error handlers and register them
from error_handlers import register_error_handlers
register_error_handlers(app)

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
    # Log the request for debugging
    logger.debug(f"Login request received: {request.method}")
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        logger.debug("AJAX login request")
    
    # Add a try-except around the entire function to catch all errors
    try:
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        form = LoginForm()
        
        if form.validate_on_submit():
            try:
                username = form.username.data.strip()
                password = form.password.data
                
                # Log action but not password
                logger.debug(f"Login attempt for username: {username}")
                
                # Test database connection before query
                try:
                    # Simple test query
                    test_user = db.session.query(User).first()
                    logger.debug(f"Database connection test succeeded")
                except Exception as db_error:
                    logger.error(f"Database connection error: {str(db_error)}")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({
                            'success': False, 
                            'message': 'Database connection error. Please try again later.'
                        }), 500
                    flash('Database connection error. Please try again later.', 'danger')
                    return render_template('login.html', form=form)
                
                # Continue with login logic
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
                logger.exception(f"Login processing error: {str(e)}")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({
                        'success': False,
                        'message': 'Login error: ' + str(e)
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
    except Exception as outer_error:
        logger.error(f"Unhandled exception in login route: {str(outer_error)}")
        logger.error(traceback.format_exc())
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False, 
                'message': 'An unexpected error occurred. Please try again.'
            }), 500
        flash('An unexpected error occurred. Please try again.', 'danger')
        return render_template('login.html', form=LoginForm())

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
            logger.debug("Opening image for encryption")
            img = PilImage.open(image_file)
            
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
                logger.debug(f"Converted image to RGB mode")
                
            # Encrypt and encode message with debug=True
            logger.debug("Encrypting message")
            encrypted_message = encrypt_message(message, password, debug=True)
            logger.debug("Encoding message into image")
            encoded_img = encode_message(img, encrypted_message, debug=True)
            
            # Save to BytesIO
            logger.debug("Saving encoded image")
            img_io = BytesIO()
            encoded_img.save(img_io, format='PNG')
            img_io.seek(0)
            image_data = img_io.getvalue()
            
            # Generate unique filename
            filename = secure_filename(image_file.filename)
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
            
            logger.debug(f"Creating database record for: {unique_filename}")
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
            logger.debug("Database records created successfully")
            
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

# Add a health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint to verify app status"""
    try:
        # Check database connection
        db_ok = False
        users_count = 0
        tables = []
        
        try:
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            users_count = User.query.count()
            db_ok = True
        except Exception as db_error:
            logger.error(f"Database health check error: {str(db_error)}")
        
        # Get app config info (removing sensitive data)
        config_info = {k: v for k, v in app.config.items() 
                      if not any(secret in k.lower() for secret in 
                                ['key', 'password', 'secret', 'token'])}
        
        # System information
        import platform
        system_info = {
            'python_version': platform.python_version(),
            'platform': platform.platform(),
        }
        
        # Prepare response
        health_data = {
            'status': 'ok' if db_ok else 'database_error',
            'database': {
                'connected': db_ok,
                'tables': tables,
                'users_count': users_count,
                'database_url': app.config.get('SQLALCHEMY_DATABASE_URI', '').replace(':///', '://***/'),
            },
            'system': system_info,
            'config': config_info
        }
        
        return jsonify(health_data)
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

# Add database creation at app startup
with app.app_context():
    try:
        logger.info("Creating database tables if needed...")
        db.create_all()
        
        # Create default admin user if it doesn't exist
        admin_exists = User.query.filter_by(role='admin').first()
        if not admin_exists:
            create_default_admin()
            
        logger.info("Database initialization complete")
    except Exception as e:
        logger.error(f"Error initializing database at startup: {str(e)}")
        logger.error(traceback.format_exc())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    
    # Use environment variable PORT if available (for Render.com), otherwise use 8080
    port = int(os.environ.get('PORT', 8080))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)

# Add this to your existing routes

@app.route('/admin-check')
@login_required
def admin_check():
    """Debug endpoint to check admin access"""
    try:
        if not current_user.role == 'admin':
            return jsonify({
                'is_admin': False,
                'message': 'You are not an admin user',
                'user_info': {
                    'username': current_user.username,
                    'role': current_user.role,
                    'email': current_user.email
                }
            })
            
        # Check if admin blueprint is registered
        is_registered = 'admin_bp.index' in app.view_functions
            
        return jsonify({
            'is_admin': True,
            'user_info': {
                'username': current_user.username,
                'role': current_user.role,
                'email': current_user.email
            },
            'admin_blueprint': {
                'registered': is_registered,
                'endpoints': [rule.endpoint for rule in app.url_map.iter_rules() 
                             if rule.endpoint.startswith('admin_bp')]
            }
        })
    except Exception as e:
        logger.error(f"Admin check error: {str(e)}")
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

# Add a debug flag to encryption and decryption calls
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
            logger.debug("Opening image for encryption")
            img = PilImage.open(image_file)
            
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
                logger.debug(f"Converted image to RGB mode")
                
            # Encrypt and encode message with debug=True
            logger.debug("Encrypting message")
            encrypted_message = encrypt_message(message, password, debug=True)
            logger.debug("Encoding message into image")
            encoded_img = encode_message(img, encrypted_message, debug=True)
            
            # Save to BytesIO
            logger.debug("Saving encoded image")
            img_io = BytesIO()
            encoded_img.save(img_io, format='PNG')
            img_io.seek(0)
            image_data = img_io.getvalue()
            
            # Generate unique filename
            filename = secure_filename(image_file.filename)
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
            
            logger.debug(f"Creating database record for: {unique_filename}")
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
            logger.debug("Database records created successfully")
            
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