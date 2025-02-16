import sys
import os
sys.path.insert(0, os.getcwd())

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from email_validator import validate_email, EmailNotValidError
import os
from werkzeug.utils import secure_filename
from PIL import Image as PilImage
import numpy as np
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from functools import wraps
import logging
import time
from flask_wtf.csrf import CSRFProtect  # Removed csrf_exempt import
import base64
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Email, Regexp  # Added Regexp
from flask_cors import CORS
from config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from io import BytesIO
from analytics import parse_logs
from magic_box import detect_suspicious
from flask_socketio import SocketIO, emit
from celery import Celery
from tasks import encrypt_task  # Updated import for Celery task
from stego import encrypt_message, encode_message  # Optionally use these
from logging.handlers import RotatingFileHandler
from api import api  # Import API Blueprint
from admin_routes import admin_bp   # Use admin_routes for admin endpoints
from models import db, User, StegoImage, ActivityLog  # Use models from models.py
from email_utils import generate_confirmation_token, confirm_token
from flask_mail import Mail, Message
from otp_utils import generate_otp, send_otp_to_phone, store_otp, verify_otp

# Configure logging
# logging.basicConfig(
#     filename='app.log',
#     level=logging.INFO,
#     format='%(asctime)s - %(levelname)s - %(message)s'
# )
# Add console logging to show errors in the console too.
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)  # Change to DEBUG
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console_handler)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Ensure Flask app logger is at DEBUG
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

def make_celery(app):
    celery = Celery(
        app.import_name, 
        broker=app.config.get('CELERY_BROKER_URL'),
        backend=app.config.get('CELERY_RESULT_BACKEND')
    )
    celery.conf.update(app.config)

    # Replace lambda with a proper ContextTask class
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    celery.Task = ContextTask
    return celery

celery = make_celery(app)

# Configure login manager
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Create upload directory
with app.app_context():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Register blueprints
app.register_blueprint(api, url_prefix='/api')
app.register_blueprint(admin_bp, url_prefix='/admin')  # All admin functionalities under /admin

# Set up rotating logging (max 1MB per file, keep 5 backups)
if not app.debug:
    file_handler = RotatingFileHandler('app.log', maxBytes=1_000_000, backupCount=5)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    app.logger.addHandler(file_handler)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    # Add a regex validator to enforce E.164 (e.g., +1234567890)
    phone_number = StringField('Phone Number', validators=[
        DataRequired(), 
        Regexp(r'^\+[1-9]\d{1,14}$', message="Invalid phone number format. Must be in E.164.")
    ])
    otp = StringField('OTP', validators=[DataRequired()])  # New field for OTP
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message="Passwords must match exactly.")
    ])
    submit = SubmitField('Register')
    
    def validate_email(self, field):
        pass

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# LSB Steganography Implementation
def encode_message(image, message):
    img_array = np.array(image).astype(np.uint8)
    
    # Convert message to binary and add delimiter.
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_message += '00000000'
    
    if len(binary_message) > img_array.size:
        raise ValueError("Message too large for this image")
    
    idx = 0
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            for k in range(3):  # RGB channels
                if idx < len(binary_message):
                    bit = int(binary_message[idx])
                    # Removed debug prints for production use.
                    img_array[i, j, k] = img_array[i, j, k] - (img_array[i, j, k] % 2)
                    img_array[i, j, k] = img_array[i, j, k] + bit
                    idx += 1
    return PilImage.fromarray(img_array)

def decode_message(image):
    try:
        img_array = np.array(image)
        binary_message = ''
        
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for k in range(3):
                    binary_message += str(img_array[i, j, k] & 1)
                    
                    if len(binary_message) % 8 == 0:
                        char = chr(int(binary_message[-8:], 2))
                        if (char == '\0'):
                            message = ''
                            for idx in range(0, len(binary_message)-8, 8):
                                message += chr(int(binary_message[idx:idx+8], 2))
                            return message
        return None
    except Exception as e:
        logging.error(f"Decoding error: {str(e)}")
        return None

# Cryptographic Functions
def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_message(message, password):
    if not message or not password:
        raise ValueError("Message and password are required")
        
    key, salt = generate_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_message = aesgcm.encrypt(nonce, message.encode(), None)
    
    combined = salt + nonce + encrypted_message
    return base64.urlsafe_b64encode(combined).decode('utf-8')

def decrypt_message(encoded_message, password):
    try:
        combined = base64.urlsafe_b64decode(encoded_message.encode('utf-8'))
        salt = combined[:16]
        nonce = combined[16:28]
        ciphertext = combined[28:]
        
        key, _ = generate_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        raise ValueError("Invalid password or corrupted message")

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
        username = form.username.data.strip()
        password_input = form.password.data  # Do not trim to preserve the user's intended password
        user = User.query.filter_by(username=username).first()
        import logging
        logging.debug(f"Login attempt for username: {username}")
        if user:
            logging.debug(f"Stored hash for user {username}: {user.password_hash}")
            logging.debug(f"Password provided: '{password_input}' (length: {len(password_input)})")
            try:
                is_valid = user.check_password(password_input)
            except Exception as e:
                logging.exception("Error during check_password:")
                return jsonify({'success': False, 'message': f'Authentication error: {str(e)}'}), 400
            logging.debug(f"check_password result: {is_valid}")
            if is_valid:
                login_user(user, remember=True)
                return jsonify({'success': True, 'redirect': url_for('dashboard')})
        else:
            logging.debug(f"No user found for username '{username}'")
        logging.debug("Invalid credentials provided.")
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Check for duplicate username, email, and phone
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already registered.", "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))
        if form.phone_number.data and User.query.filter_by(phone_number=form.phone_number.data).first():
            flash("Phone number already registered.", "danger")
            return redirect(url_for('register'))
        
        # Generate and send OTP
        otp = generate_otp()
        store_otp(form.phone_number.data.strip(), otp, expiry=30)  # Trim spaces if any
        try:
            send_otp_to_phone(form.phone_number.data.strip(), otp)
            flash("OTP sent to your phone number.", "info")
        except Exception as e:
            flash(f"Failed to send OTP: {e}", "danger")
            return redirect(url_for('register'))
        
        # Debug: log OTP values for troubleshooting.
        import logging
        logging.debug(f"OTP stored: {otp}, OTP provided: {form.otp.data.strip()}, Phone: {form.phone_number.data.strip()}")
        # Verify OTP before continuing
        if not verify_otp(form.phone_number.data.strip(), form.otp.data.strip()):
            flash("Invalid or expired OTP.", "danger")
            return redirect(url_for('register'))
        
        try:
            user = User(
                username=form.username.data, 
                email=form.email.data,
                phone_number=form.phone_number.data.strip(),
                is_verified=True  # Automatically verify the user upon successful OTP verification
            )
            try:
                user.set_password(form.password.data)
            except Exception as e:
                import logging
                logging.exception("Error in setting user password:")
                flash(f"Registration error: {str(e)}", "danger")
                return redirect(url_for('register'))
            db.session.add(user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.exception("Registration error:")
            flash("Registration failed: Please ensure all fields are correct and try again.", "danger")
            return redirect(url_for('register'))
    else:
        if request.method == 'POST':
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", "danger")
    
    return render_template('register.html', form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    # Log the token value received for debugging.
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

@csrf.exempt
@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    try:
        if 'image' not in request.files:
            raise ValueError("Missing file key: 'image'")
        image_file = request.files['image']
        if not image_file or image_file.filename == "":
            raise ValueError("No image file provided")
            
        file_data = image_file.read()
        password = request.form.get('password')
        message = request.form.get('message')
        if not password:
            raise ValueError("Missing encryption password")
        if not message:
            raise ValueError("Missing message to hide")
            
        # Process image synchronously
        img = PilImage.open(BytesIO(file_data))
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        # Use stego.py functions
        encrypted_message = encrypt_message(message, password)
        encoded_img = encode_message(img, encrypted_message)
        
        # Convert encoded image to binary and prepare for saving
        img_io = BytesIO()
        encoded_img.save(img_io, format='PNG')
        img_io.seek(0)
        image_data = img_io.read()
        
        # Create a unique filename
        filename = secure_filename(image_file.filename)
        unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
        
        # Save record into the database (assuming StegoImage has these fields)
        new_image = StegoImage(
            user_id=current_user.id,
            filename=unique_filename,
            original_filename=image_file.filename,
            image_data=image_data,
            encryption_type='LSB'
        )
        db.session.add(new_image)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'redirect': url_for('dashboard'),
            'message': 'Encryption successful'
        })
    except Exception as e:
        app.logger.error(f"Encryption error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 400

@socketio.on('connect')
def on_connect():
    emit('message', {'info': 'Connected to real-time log updates'})

# Modify the download route to accept filenames with dots using the "path" converter
@app.route('/download/<path:filename>')
@login_required
def download_image(filename):
    image = StegoImage.query.filter_by(filename=filename, user_id=current_user.id).first()
    if image is None:
        return jsonify({'success': False, 'message': 'Image not found'}), 404
    
    # Append the correct extension when calling send_file
    return send_file(
        BytesIO(image.image_data),
        mimetype='image/png',
        as_attachment=True,
        download_name=image.original_filename # Use original filename for download
    )

@app.route('/result')
@login_required
def result():
    decrypted_text = request.args.get('message', '')
    return render_template('result.html', decrypted_text=decrypted_text)

@csrf.exempt
@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    try:
        file = request.files['image']
        password = request.form['password']
        
        if not file:
            raise ValueError("No image provided")
        
        try:
            img = PilImage.open(file.stream)
            if img.mode != 'RGB':
                img = img.convert('RGB')
        except Exception as e:
            logging.error(f"Error opening or converting image: {str(e)}")
            raise ValueError("Invalid image file")
            
        ciphertext = decode_message(img)
        if not ciphertext:
            raise ValueError("No hidden message found")
            
        decrypted_message = decrypt_message(ciphertext, password)
        return jsonify({
            'success': True, 
            'redirect': url_for('result', message=decrypted_message)
        })
        
    except Exception as e:
        detailed_error = str(e)
        if "The string did not match the expected pattern" in detailed_error:
            user_message = "Decryption failed: Possibly due to an incorrect password or corrupted data."
        else:
            user_message = detailed_error
        logging.exception("Decryption error (detailed):")
        return jsonify({'success': False, 'message': user_message}), 400

@app.route('/promote/<int:user_id>')
@login_required
def promote_user(user_id):
    # Only an existing admin can promote others
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.")
        return redirect(url_for('dashboard'))

    user.role = 'admin'
    db.session.commit()
    flash(f"{user.username} has been promoted to admin.")
    return redirect(url_for('dashboard'))

@app.route('/admin/api/logs-summary', methods=['GET'])
@login_required
def logs_summary():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        with open('app.log', 'r') as f:
            data = parse_logs(f.readlines())
        return jsonify({'success': True, 'data': data})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/magic', methods=['GET'])
@login_required
def magic():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        with open('app.log', 'r') as f:
            suspects = detect_suspicious(f.readlines())
        return jsonify({'success': True, 'suspects': suspects})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f"404 error: {error}")
    return render_template('errors/404.html', error=error), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 error: {error}")
    # For debugging, optionally display error details (remove in production)
    return render_template('errors/500.html', error=error), 500

# Updated route: Request OTP (POST phone number)
@app.route('/request_otp', methods=['POST'])
def request_otp():
    phone = request.form.get('phone')
    if not phone:
        app.logger.error("Phone number is required.")
        return jsonify({'success': False, 'message': 'Phone number required'}), 400
    if not phone.startswith('+'):
        app.logger.error("Phone number must be in E.164 format.")
        return jsonify({'success': False, 'message': 'Phone number must be in E.164 format, e.g., +1234567890'}), 400
    try:
        otp = generate_otp()
        store_otp(phone, otp, expiry=30)  # Set OTP expiry to 30 seconds
        send_otp_to_phone(phone, otp)
    except Exception as e:
        app.logger.error(f"Error sending OTP: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    return jsonify({'success': True, 'message': 'OTP sent to your phone'})

# New route: Login with phone using OTP
@app.route('/login_phone', methods=['POST'])
def login_phone():
    phone = request.form.get('phone')
    otp_input = request.form.get('otp')
    if not phone or not otp_input:
        return jsonify({'success': False, 'message': 'Phone and OTP required'}), 400
    if verify_otp(phone, otp_input):
        # Try to find the user by phone number.
        from models import User
        user = User.query.filter_by(phone_number=phone).first()
        if not user:
            return jsonify({'success': False, 'message': 'No user with that phone number'}), 404
        login_user(user, remember=True)
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
    else:
        return jsonify({'success': False, 'message': 'Invalid or expired OTP'}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)