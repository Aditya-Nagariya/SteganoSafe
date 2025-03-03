from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional, Regexp
from email_validator import validate_email
import re

class LoginForm(FlaskForm):
    """Form for user login"""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    """Form for user registration with phone validation"""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20, message="Username must be between 3 and 20 characters")
    ])
    
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address")
    ])
    
    # Phone number field - made optional
    phone_number = StringField('Phone Number (Optional)', validators=[
        Optional(),
        # Basic E.164 format validation
        Regexp(r'^\+?[0-9\s\-\(\)]{6,20}$', 
               message="If provided, phone must start with + followed by country code and number")
    ])
    
    # OTP made optional for development ease
    otp = StringField('One-Time Password (OTP)', validators=[])
    
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    
    submit = SubmitField('Register')
    
    # Custom phone number cleaner
    def clean_phone_number(self):
        """Clean the phone number to E.164 format if provided"""
        if not self.phone_number.data:
            return None
            
        # Strip spaces, dashes, parentheses
        cleaned = re.sub(r'[\s\-\(\)]', '', self.phone_number.data)
        
        # Make sure it starts with +
        if cleaned and not cleaned.startswith('+'):
            cleaned = '+' + cleaned
            
        return cleaned

class EncryptForm(FlaskForm):
    """Form for encryption operation"""
    message = TextAreaField('Message', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Encrypt')

class DecryptForm(FlaskForm):
    """Form for decryption operation"""
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Decrypt')
