import os
import sys
# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, socketio, db, create_default_admin

# Initialize database and create admin user when deployed
with app.app_context():
    db.create_all()
    create_default_admin()

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    socketio.run(app, host='0.0.0.0', port=port)
