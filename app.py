import sys
import os
import logging
import traceback
import json
from contextlib import suppress
from routes.user import init_user_routes
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, send_from_directory, abort, session
import base64

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

# Import filters early to ensure they're available
try:
    import filters
    logger.info("Successfully imported filters module")
except ImportError as e:
    logger.error(f"Failed to import filters module: {e}")

sys.path.insert(0, os.getcwd())

# Run ensure_db.py to set up database
try:
    from ensure_db import ensure_database
    data_dir, db_path = ensure_database()
    logger.info(f"Database ensured at: {db_path}")
    
    # Update environment with database path
    os.environ['DATABASE_PATH'] = db_path
    logger.info(f"Set DATABASE_PATH to {os.environ['DATABASE_PATH']}")
except Exception as e:
    logger.error(f"Database initialization error: {str(e)}")
    logger.error(traceback.format_exc())

# Continue with regular imports
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort, session
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

# Add this near the top with other imports
try:
    from debug_routes import init_debug_routes
except ImportError:
    # Create a dummy function if the module doesn't exist
    def init_debug_routes(app):
        pass

# Import app modules
from config import Config
from stego import encrypt_message, decrypt_message, encode_message, decode_message, encode_message_with_method
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

# Fix session configuration to improve persistence
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_REFRESH_EACH_REQUEST'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
app.config['SESSION_KEY_PREFIX'] = 'steganosafe_'
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

# Configure SQLAlchemy for better durability
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,  # Verify connections before using
    'pool_recycle': 280,    # Recycle connections before idle timeout
    'pool_timeout': 30,     # Wait 30s for connection
    'connect_args': {       # SQLite specific settings
        'timeout': 30,      # Wait 30s for locked database
        'check_same_thread': False  # Allow multithreaded access
    }
}

# Add this immediately after initializing the app:
from filters import register_filters
register_filters(app)

# Add this near the beginning of your app.py file, right after creating the app instance
# Check for required directories and favicon
def check_static_files():
    """Check that required static files exist"""
    static_img_dir = os.path.join(app.root_path, 'static/img')
    favicon_path = os.path.join(static_img_dir, 'favicon.ico')
    
    if not os.path.exists(static_img_dir):
        logger.warning("Static img directory doesn't exist. Creating it.")
        os.makedirs(static_img_dir, exist_ok=True)
    
    if not os.path.exists(favicon_path):
        logger.warning("Favicon not found. Generating it.")
        try:
            from create_favicon import create_simple_favicon
            create_simple_favicon()
            logger.info("Favicon generated successfully.")
        except Exception as e:
            logger.error(f"Failed to generate favicon: {e}")

check_static_files()

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

# Import the new blueprint
from routes.theme_routes import theme_bp

# Register the blueprint
app.register_blueprint(theme_bp)

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
            logger.debug(f"User {current_user.username} already authenticated, redirecting to dashboard")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'message': 'Already logged in',
                    'redirect': url_for('dashboard')
                })
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
                    logger.debug(f"Login successful for user: {username}")
                    
                    # Force session creation and persistence
                    session.permanent = True
                    session['user_id'] = user.id
                    session['username'] = user.username
                    session['role'] = user.role
                    
                    # Force session save
                    session.modified = True
                    
                    # Log activity
                    activity = ActivityLog(user_id=user.id, action="User logged in")
                    db.session.add(activity)
                    db.session.commit()
                    
                    # Prepare redirect URL
                    next_page = request.args.get('next')
                    redirect_url = next_page or url_for('dashboard')
                    logger.debug(f"Redirect URL: {redirect_url}")
                    
                    # Check if default admin credentials
                    if user.username == 'admin' and user.role == 'admin' and password == 'admin123':
                        flash('You are using default admin credentials. Please change your password!', 'warning')
                        
                    # Handle AJAX requests differently
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        logger.debug(f"Sending JSON response for AJAX login with redirect to {redirect_url}")
                        return jsonify({
                            'success': True,
                            'message': 'Login successful!',
                            'redirect': redirect_url,
                            'user_id': user.id,  # Add user info to help debug
                            'is_authenticated': current_user.is_authenticated,
                            'session_id': session.sid if hasattr(session, 'sid') else None
                        })
                    else:
                        logger.debug(f"Redirecting after non-AJAX login to {redirect_url}")
                        return redirect(redirect_url)
                else:
                    logger.warning(f"Failed login attempt for username: {username}")
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
            logger.debug(f"Form validation failed for AJAX login: {form.errors}")
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
    try:
        # Log debugging information
        logger.debug(f"Dashboard requested by user: {current_user.username} (id: {current_user.id})")
        
        # Get images with error handling
        try:
            images = StegoImage.query.filter_by(user_id=current_user.id).all()
            logger.debug(f"Found {len(images)} images for user")
        except Exception as db_error:
            logger.error(f"Database error fetching images: {str(db_error)}")
            logger.error(traceback.format_exc())
            flash("Error loading your images. Please try again later.", "danger")
            images = []
            
        # Render template with additional data for debugging
        return render_template(
            'dashboard.html', 
            images=images, 
            user=current_user,
            debug_info={
                'timestamp': datetime.utcnow(),
                'user_id': current_user.id
            }
        )
    except Exception as e:
        logger.error(f"Unhandled exception in dashboard route: {str(e)}")
        logger.error(traceback.format_exc())
        flash("An unexpected error occurred. Please try again later.", "danger")
        return redirect(url_for('home'))


# Also add a debug endpoint to check what's happening
@app.route('/debug/dashboard')
@login_required
def debug_dashboard():
    """Debug endpoint to check dashboard data"""
    if not app.debug:
        return jsonify({'error': 'Only available in debug mode'}), 403
        
    try:
        # Get user info
        user_info = {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'role': current_user.role
        }
        
        # Get images info
        images = StegoImage.query.filter_by(user_id=current_user.id).all()
        images_info = []
        
        for img in images:
            images_info.append({
                'id': img.id,
                'filename': img.filename,
                'original_filename': img.original_filename,
                'created_at': str(img.created_at) if hasattr(img, 'created_at') else None,
                'has_image_data': bool(img.image_data)
            })
            
        # Get database tables
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Get stego_images table columns
        columns = []
        if 'stego_images' in tables:
            columns = [column['name'] for column in inspector.get_columns('stego_images')]
            
        return jsonify({
            'user': user_info,
            'images_count': len(images),
            'images': images_info,
            'database': {
                'tables': tables,
                'stego_images_columns': columns
            }
        })
    except Exception as e:
        logger.error(f"Debug dashboard error: {str(e)}")
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    if request.method == 'GET':
        # Import encryption methods from stego.py
        from stego import AVAILABLE_ENCRYPTION_METHODS, get_default_encryption_method
        return render_template('encrypt.html',
                              encryption_methods=AVAILABLE_ENCRYPTION_METHODS,
                              default_method=get_default_encryption_method())
    
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
            
            # Get the encryption method from form
            encryption_method = request.form.get('encryption_method', 'LSB')
            logger.debug(f"Using encryption method: {encryption_method}")
                
            # Encrypt and encode message with debug=True
            logger.debug("Encrypting message")
            encrypted_message = encrypt_message(message, password, debug=True)
            
            logger.debug("Encoding message into image")
            # Use encode_message_with_method function from stego module
            encoded_img = encode_message_with_method(
                img, message, password, method=encryption_method, debug=True
            )
            
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
            
            # Use explicit database transaction for reliability
            try:
                # Create database record
                new_image = StegoImage(
                    user_id=current_user.id,
                    filename=unique_filename,
                    original_filename=image_file.filename,
                    image_data=image_data,
                    encryption_type=encryption_method  # Store the actual method used
                )
                
                db.session.add(new_image)
                
                # Log activity
                activity = ActivityLog(
                    user_id=current_user.id,
                    action=f"Encrypted image: {image_file.filename}"
                )
                
                db.session.add(activity)
                
                # Explicitly flush to detect errors early
                db.session.flush()
                
                # Now commit the transaction
                db.session.commit()
                logger.debug("Database records created successfully")
                
                # Double check the image was stored by reading it back
                verification = StegoImage.query.filter_by(filename=unique_filename).first()
                if not verification or not verification.image_data:
                    logger.warning(f"Image verification failed for {unique_filename}!")
                else:
                    logger.debug(f"Image verified in database with ID {verification.id}")
                
            except Exception as db_error:
                db.session.rollback()
                logger.error(f"Database error: {str(db_error)}")
                return jsonify({
                    'success': False,
                    'message': f'Database error: {str(db_error)}'
                }), 500
            
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
    try:
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
                logger.debug(f"Attempting to decrypt uploaded image: {file.filename}")
                img = PilImage.open(file)
                
                if img.mode != 'RGB':
                    logger.debug(f"Converting image from {img.mode} to RGB mode")
                    img = img.convert('RGB')
                
                # Try to use the new direct_lsb_decode method first
                from stego import direct_lsb_decode
                logger.debug(f"Trying direct_lsb_decode on image")
                ciphertext = direct_lsb_decode(img, debug=True)
                
                if not ciphertext:
                    logger.debug(f"Direct decoding failed, trying standard decode_message")
                    from stego import decode_message
                    ciphertext = decode_message(img, method='AUTO', debug=True)
                
                if not ciphertext:
                    logger.warning("No hidden message found in image")
                    return jsonify({'success': False, 'message': 'No hidden message found in this image. Please verify this is an encrypted image.'}), 400
                
                logger.debug(f"Successfully extracted ciphertext of length {len(ciphertext)}")
                
                logger.debug("Attempting to decrypt extracted ciphertext")
                try:
                    decrypted_message = decrypt_message(ciphertext, password, debug=True)
                    logger.info("Message successfully decrypted")
                    
                    # Log a successful decryption activity
                    activity = ActivityLog(
                        user_id=current_user.id,
                        action=f"Decrypted uploaded image: {file.filename}"
                    )
                    db.session.add(activity)
                    db.session.commit()
                    
                    # Return successful response with the decrypted message
                    return jsonify({
                        'success': True,
                        'message': 'Message decrypted successfully',
                        'decrypted_message': decrypted_message
                    })
                except Exception as decrypt_error:
                    logger.warning(f"Standard decryption failed: {decrypt_error}")
                    logger.debug("Trying safe_decrypt method as fallback")
                    from stego import decrypt_message_safe
                    try:
                        decrypted_message = decrypt_message_safe(ciphertext, password, debug=True)
                        logger.info("Message successfully decrypted with safe method")
                        
                        # Log activity
                        activity = ActivityLog(
                            user_id=current_user.id,
                            action=f"Decrypted uploaded image: {file.filename} (using safe decrypt)"
                        )
                        db.session.add(activity)
                        db.session.commit()
                        
                        return jsonify({
                            'success': True,
                            'message': 'Message decrypted successfully (using safe method)',
                            'decrypted_message': decrypted_message
                        })
                    except Exception as safe_decrypt_error:
                        logger.error(f"Both decryption methods failed: {safe_decrypt_error}")
                        return jsonify({'success': False, 'message': f'Decryption failed: {str(safe_decrypt_error)}. Please check your password.'}), 400
            except ValueError as e:
                logger.error(f"Value error during decryption: {str(e)}")
                return jsonify({'success': False, 'message': f'Decryption error: {str(e)}'}), 400
            except Exception as e:
                app.logger.exception(f"Decryption error: {str(e)}")
                return jsonify({'success': False, 'message': f'Error during decryption: {str(e)}'}), 400
        except Exception as e:
            app.logger.exception(f"Decrypt route error: {str(e)}")
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500
    except Exception as e:
        app.logger.exception(f"Decrypt route error: {str(e)}")
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500

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
            return jsonify({'success': False, 'message': 'No user found with this phone number'}), 404
        
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
@login_required
@app.route('/admin-check')
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

@app.route('/check-session')
def check_session():
    """Debug endpoint to check session status"""
    data = {
        'authenticated': current_user.is_authenticated,
        'session_data': {k: session.get(k) for k in session if k != '_flashes'},
        'user_info': None
    }
    
    if current_user.is_authenticated:
        data['user_info'] = {
            'id': current_user.id,
            'username': current_user.username,
            'role': current_user.role
        }
    
    return jsonify(data)

# Add this near the other app template filters at the end of your app.py file
@app.template_test('containing')
def containing_test(value, other):
    """Check if a string contains another string"""
    return other.lower() in str(value).lower() if value and other else False

# Update the favicon routes for better compatibility
@app.route('/favicon.ico')
def favicon():
    """Serve the favicon.ico file"""
    return send_from_directory(
        os.path.join(app.root_path, 'static', 'img'),
        'favicon.ico', 
        mimetype='image/vnd.microsoft.icon'
    )

@app.route('/apple-touch-icon.png')
def apple_touch_icon():
    """Serve the apple-touch-icon.png file"""
    return send_from_directory(
        os.path.join(app.root_path, 'static', 'img'),
        'apple-touch-icon.png', 
        mimetype='image/png'
    )

@app.route('/apple-touch-icon-precomposed.png')
def apple_touch_icon_precomposed():
    """Serve the apple-touch-icon-precomposed.png file"""
    return send_from_directory(
        os.path.join(app.root_path, 'static', 'img'),
        'apple-touch-icon-precomposed.png', 
        mimetype='image/png'
    )

# After registering other blueprints (near line 100), add:
init_user_routes(app)

# If you want a simple fix and don't want to add the entire user routes module,
# you can alternatively just add this route directly in app.py:
@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html', user=current_user)

# Add this after registering other blueprints
if app.debug:
    init_debug_routes(app)

@login_required
@app.route('/decrypt-stored', methods=['POST'])
def decrypt_stored():
    """Decrypt a stored image with enhanced error recovery"""
    # Log that we entered this route
    logger.info(f"Decrypt-stored route called by user {current_user.username}")
    try:
        image_id = request.form.get('image_id')
        password = request.form.get('password')
        encryption_method = request.form.get('encryption_method', 'AUTO')  # Default to AUTO
        try_recovery = request.form.get('try_recovery', 'false').lower() == 'true'
        
        logger.info(f"Decrypting stored image {image_id} using method {encryption_method}")
        
        if not image_id or not password:
            return jsonify({'success': False, 'message': 'Image ID and password are required'}), 400
        
        # Get the image from database
        image = StegoImage.query.filter_by(id=image_id, user_id=current_user.id).first()
        if not image:
            logger.warning(f"Image {image_id} not found for user {current_user.id}")
            return jsonify({'success': False, 'message': 'Image not found'}), 404
        
        # Check if image data exists
        if not image.image_data:
            logger.error(f"Image {image_id} has no data")
            return jsonify({'success': False, 'message': 'Image has no data'}), 400
            
        # Use the API method with detailed error handling
        try:
            # Use JSON request format for the API endpoint with our parameters 
            api_response = api_decrypt_saved_image()
            # If it's a successful response, return it
            if api_response.status_code == 200:
                return api_response
            
            # If recovery isn't enabled but might help, suggest it
            if not try_recovery and api_response.status_code == 400:
                try:
                    response_data = json.loads(api_response.data)
                    if response_data.get('recovery_available'):
                        # Modify the response to suggest enabling recovery mode
                        response_data['message'] += " Try enabling recovery mode for better results."
                        if 'suggestions' in response_data:
                            response_data['suggestions'].append("Enable recovery mode to try more aggressive decryption methods")
                        return jsonify(response_data), 400
                except Exception:
                    pass
                
            # Otherwise just return the original response
            return api_response
        except Exception as e:
            logger.error(f"Error calling API endpoint: {e}")
            return jsonify({
                'success': False,
                'message': f"Failed to decrypt image: {str(e)}"
            }), 500
    except Exception as e:
        logger.error(f"Error in decrypt-stored: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'message': f"An error occurred during decryption: {str(e)}"
        }), 500

# Add improved API decrypt_saved_image route to app.py
@app.route('/api/decrypt_saved_image', methods=['POST'])
@login_required
def api_decrypt_saved_image():
    """API endpoint for decrypting saved images with improved error handling and recovery"""
    start_time = time.time()
    try:
        # Get JSON data
        data = request.get_json()
        if not data:
            logger.error("No JSON data in request")
            return jsonify({
                'success': False,
                'message': 'No data provided'
            }), 400
        
        # Extract parameters
        image_id = data.get('image_id')
        password = data.get('password')
        method = data.get('method', 'LSB')
        try_recovery = data.get('try_recovery', False)  # New parameter to enable recovery mode
        
        if not image_id or not password:
            logger.error("Missing image_id or password")
            return jsonify({
                'success': False,
                'message': 'Image ID and password required'
            }), 400
        
        # Log the decryption attempt
        logger.info(f"API decrypt request for image {image_id} using {method}")
        
        # Lookup the image - using get() instead of first() to handle None case better
        image = StegoImage.query.filter_by(id=image_id, user_id=current_user.id).first()
        if not image:
            logger.error(f"Image {image_id} not found for user {current_user.id}")
            return jsonify({
                'success': False,
                'message': 'Image not found'
            }), 404
        
        # Import the necessary functions locally to avoid circular imports
        from io import BytesIO
        from PIL import Image as PilImage
        
        # Load the image from binary data
        try:
            logger.debug(f"Loading image data of size {len(image.image_data) if image.image_data else 0} bytes")
            img_io = BytesIO(image.image_data)
            img = PilImage.open(img_io)
            if img.mode != 'RGB':
                logger.debug(f"Converting image from {img.mode} to RGB mode")
                img = img.convert('RGB')
        except Exception as e:
            logger.error(f"Error loading image: {e}")
            return jsonify({
                'success': False,
                'message': f"Error loading image: {str(e)}"
            }), 500
        
        # First try direct_lsb_decode
        ciphertext = None
        try:
            logger.debug("Starting direct LSB decoding")
            from stego import direct_lsb_decode
            ciphertext = direct_lsb_decode(img, debug=True)
            if ciphertext:
                logger.debug(f"Direct LSB decoding yielded {len(ciphertext)} bytes")
        except Exception as e:
            logger.error(f"Direct LSB decoding error: {e}")
        
        # If direct decoding failed, try standard decode_message
        if not ciphertext:
            try:
                logger.debug(f"Trying {method} method")
                from stego import decode_message
                ciphertext = decode_message(img, method=method, debug=True)
                if ciphertext:
                    logger.debug(f"Standard decoding yielded {len(ciphertext)} bytes")
            except Exception as e:
                logger.error(f"Standard decode_message error: {e}")
        
        # If we still don't have a message, return error
        if not ciphertext:
            logger.error("No hidden message found in the image")
            return jsonify({
                'success': False,
                'message': 'No hidden message found in this image'
            }), 400
        
        # Try to decrypt the message
        try:
            logger.debug(f"Decrypting message of length {len(ciphertext)}")
            if try_recovery:
                # Check if we should use advanced password recovery
                try:
                    from cryptography_utils import attempt_password_variants
                    from stego import decrypt_message_safe
                    def decrypt_wrapper(data, pwd):
                        return decrypt_message_safe(data, pwd, debug=True)
                    logger.debug("Attempting password variants")
                    # Try password variants
                    success, decrypted, used_password = attempt_password_variants(
                        ciphertext, password, decrypt_wrapper)
                    if success:
                        # Log success with password correction
                        if used_password != password:
                            logger.info(f"Decryption succeeded with corrected password: '{used_password}'")
                            # Record activity
                            activity = ActivityLog(
                                user_id=current_user.id,
                                action=f"Decrypted image {image.original_filename} (with auto-correction)"
                            )
                            db.session.add(activity)
                            db.session.commit()
                        return jsonify({
                            'success': True,
                            'decrypted_message': f"[AUTO-CORRECTED] {decrypted}",
                            'password_corrected': True
                        })
                except Exception as e:
                    logger.error(f"Password variants attempt failed: {e}")
            
            # Standard decryption flow
            try:
                logger.debug("Attempting standard decryption")
                from stego import decrypt_message
                decrypted_message = decrypt_message(ciphertext, password, debug=True)
                logger.debug("Standard decryption successful")
            except Exception as decrypt_error:
                logger.error(f"Standard decryption failed: {decrypt_error}")
                if try_recovery:
                    # If recovery mode, try with auth bypass
                    logger.info("Attempting recovery with auth bypass")
                    try:
                        from stego import decrypt_message
                        decrypted_message = decrypt_message(ciphertext, password, debug=True, bypass_auth=True)
                        logger.debug("Auth bypass decryption successful")
                    except Exception as bypass_error:
                        logger.error(f"Auth bypass failed: {bypass_error}")
                        # Then try safe decrypt as fallback
                        from stego import decrypt_message_safe
                        decrypted_message = decrypt_message_safe(ciphertext, password, debug=True)
                        logger.debug("Safe decryption successful")
                else:
                    # Then try safe decrypt as fallback
                    from stego import decrypt_message_safe
                    decrypted_message = decrypt_message_safe(ciphertext, password, debug=True)
                    logger.debug("Safe decryption successful")
            
            # Log success
            logger.info(f"Successfully decrypted message from image {image_id}")
            try:
                # Record activity - use try/except to ensure database errors don't stop successful response
                activity = ActivityLog(
                    user_id=current_user.id,
                    action=f"Decrypted image {image.original_filename}"
                )
                db.session.add(activity)
                db.session.commit()
                logger.debug("Activity log recorded successfully")
            except Exception as db_error:
                logger.error(f"Failed to record activity log: {db_error}")
                # Don't let DB errors prevent successful response
                db.session.rollback()
            
            # Success response
            return jsonify({
                'success': True,
                'decrypted_message': decrypted_message
            })
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            error_message = str(e)
            suggestions = []
            if 'password' in error_message.lower():
                suggestions = [
                    "Double-check your password",
                    "Passwords are case-sensitive",
                    "Make sure you're using the same password used during encryption"
                ]
            if 'tag' in error_message.lower() or 'auth' in error_message.lower():
                suggestions.append("The encrypted data may be corrupted")
                suggestions.append("Try enabling recovery mode for more aggressive decryption")
            return jsonify({
                'success': False,
                'message': 'Failed to decrypt message. Please check your password or try a different decryption method.',
                'details': error_message,
                'suggestions': suggestions,
                'recovery_available': True
            }), 400
    except Exception as e:
        logger.error(f"API decrypt error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500
    finally:
        end_time = time.time()
        app.logger.debug(f"API request to /api/decrypt_saved_image took {end_time - start_time:.4f}s")

app.config['FORCE_LSB_ENCRYPTION'] = True  # Force all methods to use LSB for now