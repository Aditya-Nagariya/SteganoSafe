#!/bin/bash

# Comprehensive deployment script that fixes all issues
echo "===== Steganography App Deployment ====="
echo "Starting deployment process..."

# 1. Create required directories
mkdir -p data/uploads
chmod -R 777 data

# 2. Fix database issues
python db_fix.py
python db_check.py

# 3. Apply migrations & ensure DB
python ensure_db.py

# 4. Set environment variables
export FLASK_APP=app.py
export FLASK_DEBUG=True

# 5. Run application
echo "Starting application..."
python app.py
