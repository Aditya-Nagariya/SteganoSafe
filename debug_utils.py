"""
Debug utility functions for the application.
"""
import logging

def debug_form_validation(form):
    """Debug helper to print detailed form validation errors"""
    logging.debug("Form validation errors:")
    for field_name, errors in form.errors.items():
        field = getattr(form, field_name, None)
        field_value = getattr(field, 'data', 'No data')
        logging.debug(f"Field '{field_name}' (value: {field_value}) has errors: {errors}")
        
        # If the field has validators, check each one
        if hasattr(field, 'validators'):
            logging.debug(f"Validators for {field_name}:")
            for validator in field.validators:
                logging.debug(f" - {validator.__class__.__name__}")

def check_phone_format(phone):
    """Check if a phone number is in E.164 format and fix it if possible"""
    import re
    
    if not phone:
        return None, "Phone number is empty"
        
    # Remove all non-digit characters except the leading +
    clean_phone = re.sub(r'[^\d+]', '', phone)
    
    # Add + if missing
    if not clean_phone.startswith('+'):
        clean_phone = '+' + clean_phone
    
    # Basic validation - should start with + and have at least 7 digits
    if not re.match(r'^\+\d{7,15}$', clean_phone):
        return None, f"Invalid phone format: {clean_phone} (should be E.164 format like +1234567890)"
    
    return clean_phone, None
