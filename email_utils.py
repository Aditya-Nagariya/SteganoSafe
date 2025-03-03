"""
Email utility functions for sending emails and handling tokens
"""
import os
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask_mail import Message
import logging

def generate_confirmation_token(email):
    """
    Generate a secure token for email confirmation
    
    Args:
        email: The email address to encode in the token
        
    Returns:
        str: URL safe token
    """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config.get('SECURITY_PASSWORD_SALT', 'email-confirm-salt'))

def confirm_token(token, expiration=3600):
    """
    Verify if a token is valid and not expired
    
    Args:
        token: The token to verify
        expiration: Number of seconds until token expires (default: 1 hour)
        
    Returns:
        str: The email address encoded in the token, or None if invalid
    """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=current_app.config.get('SECURITY_PASSWORD_SALT', 'email-confirm-salt'),
            max_age=expiration
        )
        return email
    except Exception as e:
        logging.error(f"Token validation error: {str(e)}")
        return None

def send_confirmation_email(user):
    """
    Send an email with a confirmation link
    
    Args:
        user: User object that needs email confirmation
    """
    from flask import url_for
    from flask_mail import current_app
    
    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    
    subject = "Please confirm your email"
    html = f"""
    <h2>Welcome to SteganoSafe!</h2>
    <p>Please confirm your email by clicking the link below:</p>
    <p><a href="{confirm_url}">Confirm Email</a></p>
    <p>This link will expire in 1 hour.</p>
    <p>If you did not register on our site, please ignore this email.</p>
    """
    
    # Only send in production, log in development
    if current_app.config['DEBUG']:
        logging.info(f"DEVELOPMENT: Email confirmation link for {user.email}: {confirm_url}")
    else:
        try:
            msg = Message(
                subject=subject,
                recipients=[user.email],
                html=html,
                sender=current_app.config['MAIL_DEFAULT_SENDER']
            )
            from flask_mail import Mail
            mail = Mail(current_app)
            mail.send(msg)
        except Exception as e:
            logging.error(f"Failed to send confirmation email: {str(e)}")
