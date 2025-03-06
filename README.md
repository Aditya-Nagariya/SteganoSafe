# SteganoSafe

A web application for steganography - hiding messages in images.

## Setup Instructions

1. Make sure you have Python 3.8+ and pip installed
2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the initialization script:
   ```bash
   ./init.sh
   ```
   This will set up the required directories and generate favicon files.

4. Run the application:
   ```bash
   python app.py
   ```

5. Access the application at: http://localhost:8080

## Default Admin Account

Username: admin
Password: admin123

## Features

- Encrypt messages in images
- Decrypt messages from images
- User management with roles (admin, user)
- Analytics dashboard
- Activity logging

## Directory Structure

- `/templates` - HTML templates
- `/static` - Static assets (CSS, JS, images)
- `/static/img` - Image assets including favicon
- `/static/uploads` - Uploaded images (created at runtime)
