from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from config import Config
import logging

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    return serializer.dumps(email, salt='email-confirm-salt')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=expiration)
    except SignatureExpired as e:
        logging.exception(f"Token expired: {token}")
        return False
    except BadSignature as e:
        logging.exception(f"Bad token signature: {token}")
        return False
    except Exception as e:
        logging.exception(f"Token validation error for token: {token}")
        return False
    return email
