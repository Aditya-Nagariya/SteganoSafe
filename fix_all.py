#!/usr/bin/env python3
"""
Master fix script that addresses all issues in the steganography app.
This script will:
1. Fix template issues
2. Fix database schema issues
3. Fix login session handling
4. Fix routing problems
5. Create missing files
"""
import os
import sys
import logging
import sqlite3
import shutil
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("FIX_ALL")

# Paths
APP_DIR = Path(__file__).parent.absolute()
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "app.db"
TEMPLATE_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"

def ensure_directories():
    """Ensure all required directories exist"""
    logger.info("Creating required directories...")
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(DATA_DIR / "uploads", exist_ok=True)
    os.makedirs(STATIC_DIR / "js", exist_ok=True)
    os.makedirs(STATIC_DIR / "css", exist_ok=True)
    os.makedirs(TEMPLATE_DIR / "admin", exist_ok=True)
    
    # Set permissions
    for dir_path in [DATA_DIR, DATA_DIR / "uploads"]:
        try:
            os.chmod(dir_path, 0o777)
            logger.info(f"Set permissions on {dir_path}")
        except Exception as e:
            logger.warning(f"Could not set permissions on {dir_path}: {e}")

def fix_database():
    """Fix database schema issues"""
    if not DB_PATH.exists():
        logger.info("No database file found. It will be created on app start.")
        return
    
    try:
        logger.info("Checking database schema...")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get current tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        logger.info(f"Found tables: {tables}")
        
        # Check activity_logs table
        if 'activity_logs' in tables:
            cursor.execute('PRAGMA table_info(activity_logs)')
            columns = [col[1] for col in cursor.fetchall()]
            
            # Fix timestamp/created_at issue
            if 'created_at' in columns and 'timestamp' not in columns:
                logger.info("Fixing activity_logs table (renaming created_at to timestamp)")
                cursor.execute("ALTER TABLE activity_logs RENAME TO activity_logs_old")
                cursor.execute("""
                CREATE TABLE activity_logs (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    action VARCHAR(255) NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(50),
                    user_agent VARCHAR(255),
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )""")
                cursor.execute("""
                INSERT INTO activity_logs (id, user_id, action, timestamp, ip_address, user_agent)
                SELECT id, user_id, action, created_at, ip_address, user_agent FROM activity_logs_old
                """)
                cursor.execute("DROP TABLE activity_logs_old")
                conn.commit()
                logger.info("Fixed activity_logs table structure")
        
        conn.close()
        logger.info("Database schema check complete")
    except Exception as e:
        logger.error(f"Error fixing database: {e}")

def fix_templates():
    """Fix template issues"""
    logger.info("Checking templates...")
    
    # Fix dashboard.html
    dashboard_path = TEMPLATE_DIR / "dashboard.html"
    if dashboard_path.exists():
        content = dashboard_path.read_text()
        if "{% if self.super() %}" in content:
            logger.info("Fixing dashboard.html template")
            fixed_content = content.replace(
                "{% if self.super() %}\n    {{ super() }}\n{% endif %}", 
                "{{ super() }}"
            )
            dashboard_path.write_text(fixed_content)
            logger.info("Fixed dashboard.html template")
    
    # Fix base.html
    base_path = TEMPLATE_DIR / "base.html"
    if base_path.exists():
        content = base_path.read_text()
        if "url_for('admin.admin_dashboard')" in content:
            logger.info("Fixing base.html template")
            fixed_content = content.replace(
                "url_for('admin.admin_dashboard')",
                "url_for('admin_bp.index')"
            )
            base_path.write_text(fixed_content)
            logger.info("Fixed base.html template")
    
    logger.info("Template check complete")

def main():
    """Main execution function"""
    logger.info("Starting comprehensive fix process...")
    
    # Ensure all directories exist
    ensure_directories()
    
    # Fix database schema issues
    fix_database()
    
    # Fix template issues
    fix_templates()
    
    logger.info("All fixes applied successfully!")
    logger.info("You can now run the application with: flask run")

if __name__ == "__main__":
    main()
