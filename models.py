from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin

# Initialize SQLAlchemy
db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    images = db.relationship('StegoImage', backref='user', lazy=True, cascade="all, delete-orphan")
    activities = db.relationship('ActivityLog', backref='user', lazy=True, cascade="all, delete-orphan")
    
    @property
    def is_admin(self):
        """Check if the user has admin role"""
        return self.role == 'admin'
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if password is correct"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class StegoImage(db.Model):
    __tablename__ = 'stego_images'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    image_data = db.Column(db.LargeBinary, nullable=True)
    encryption_type = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add this property to maintain backward compatibility
    @property
    def timestamp(self):
        """Alias for created_at to maintain compatibility"""
        return self.created_at
    
    def __repr__(self):
        return f'<StegoImage {self.filename}>'

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50), nullable=True)
    
    def __repr__(self):
        return f'<ActivityLog {self.id}: {self.action}>'

# Add this function at the end of the file

def ensure_schema_compatibility():
    """Ensure the database schema is compatible with current models"""
    from sqlalchemy import inspect
    
    # Get engine from db
    engine = db.get_engine()
    inspector = inspect(engine)
    
    try:
        # Check stego_images table
        if 'stego_images' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('stego_images')]
            
            # Check if we need to add created_at column
            if 'created_at' not in columns and 'timestamp' not in columns:
                # Need to use raw SQL because SQLAlchemy doesn't support adding columns easily
                with engine.connect() as conn:
                    conn.execute('ALTER TABLE stego_images ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP')
                
        print("Database schema compatibility checked")
    except Exception as e:
        import logging
        logging.error(f"Error checking schema compatibility: {e}")
        import traceback
        logging.error(traceback.format_exc())
