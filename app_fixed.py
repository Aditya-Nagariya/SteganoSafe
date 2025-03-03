import os
import logging
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from io import BytesIO
from PIL import Image as PilImage
import re

from models import db, User, StegoImage, ActivityLog
from stego import encrypt_message, decrypt_message, encode_message, decode_message
from forms import LoginForm, RegisterForm, EncryptForm, DecryptForm
from config import Config
from admin_routes import admin_bp
from api import api
from otp_utils import generate_otp, send_otp_to_phone, store_otp, verify_otp

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

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
CORS(app)

# Configure login manager
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Register blueprints
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(api, url_prefix='/api')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

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
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data if hasattr(form, 'remember') else False)
            
            # Log activity
            activity = ActivityLog(user_id=user.id, action="User logged in")
            db.session.add(activity)
            db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    
    if form.validate_on_submit():
        try:
            # Check for existing users
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already taken', 'danger')
                return render_template('register.html', form=form)
                
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered', 'danger')
                return render_template('register.html', form=form)
            
            # Clean phone if provided
            phone = None
            if form.phone_number.data:
                phone = re.sub(r'[\s\-\(\)]', '', form.phone_number.data)
                if not phone.startswith('+'):
                    phone = '+' + phone
                    
                if User.query.filter_by(phone_number=phone).first():
                    flash('Phone number already registered', 'danger')
                    return render_template('register.html', form=form)
            
            # Create new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                phone_number=phone,
                is_verified=True  # Auto-verify in dev mode
            )
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.commit()
            
            # Log activity
            activity = ActivityLog(user_id=user.id, action="User registered")
            db.session.add(activity)
            db.session.commit()
            
            flash('Registration successful! Please log in', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            logger.exception(f"Registration error: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template('register.html', form=form)

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
            image = PilImage.open(image_file)
            
            # Convert to RGB if needed
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            # Encrypt and encode message
            encrypted_message = encrypt_message(message, password)
            encoded_image = encode_message(image, encrypted_message)
            
            # Save to BytesIO
            img_io = BytesIO()
            encoded_image.save(img_io, 'PNG')
            img_io.seek(0)
            image_data = img_io.getvalue()
            
            # Create filename and save to DB
            filename = secure_filename(image_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            
            new_image = StegoImage(
                user_id=current_user.id,
                filename=unique_filename,
                original_filename=image_file.filename,
                image_data=image_data,
                encryption_type='LSB'
            )
            
            db.session.add(new_image)
            
            # Add activity log
            activity = ActivityLog(
                user_id=current_user.id,
                action=f"Created steganography image: {image_file.filename}"
            )
            db.session.add(activity)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Message encrypted and hidden successfully!',
                'redirect': url_for('dashboard')
            })
            
        except ValueError as e:
            # Specific errors from stego module
            return jsonify({'success': False, 'message': str(e)}), 400
        except Exception as e:
            logger.exception("Image processing error")
            return jsonify({'success': False, 'message': f"Error processing image: {str(e)}"}), 400
            
    except Exception as e:
        logger.exception("Encryption error")
        return jsonify({'success': False, 'message': f"Encryption error: {str(e)}"}), 500

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt():
    if request.method == 'GET':
        return render_template('decrypt.html')
    
    # Rest of decrypt function...
    # (Similar structure to encrypt function)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download/<filename>')
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
        return jsonify({'success': False, 'message': 'Phone number required'}), 400
    
    # Clean phone number
    phone = re.sub(r'[\s\-\(\)]', '', phone)
    if not phone.startswith('+'):
        phone = '+' + phone
    
    try:
        otp = generate_otp()
        store_otp(phone, otp, expiry=300)  # 5 minutes
        
        # In development, don't actually send SMS
        if app.debug:
            logger.info(f"DEV MODE: OTP for {phone} is {otp}")
        else:
            send_otp_to_phone(phone, otp)
            
        return jsonify({'success': True, 'message': 'OTP sent to your phone'})
    except Exception as e:
        logger.error(f"Error sending OTP: {str(e)}")
        return jsonify({'success': False, 'message': f"Error: {str(e)}"}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html', error=str(e) if app.debug else None), 500

# Create default admin user
def create_default_admin():
    try:
        admin_exists = User.query.filter_by(role='admin').first() is not None
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
            logger.info("Default admin user created")
            print("\n" + "*" * 80)
            print("* DEFAULT ADMIN CREATED:")
            print("* Username: admin")
            print("* Password: admin123")
            print("*" * 80 + "\n")
    except Exception as e:
        logger.error(f"Error creating default admin: {str(e)}")
        db.session.rollback()

if __name__ == '__main__':
    with app.app_context():
        # Ensure tables exist
        db.create_all()
        # Create directories
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        # Create default admin user if needed
        create_default_admin()
    
    # Start the app
    app.run(debug=True, host='0.0.0.0', port=8080)
