#!/usr/bin/env python3
"""
MASTER FIX SCRIPT - Fixes all issues in the application with one command
"""
import os
import sys
import logging
import subprocess
import sqlite3
import re
import importlib
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("MASTER_FIX")

# Paths
APP_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = APP_DIR / "data"
TEMPLATE_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"
DB_PATH = DATA_DIR / "app.db"

def fix_database_schema():
    """Fix database schema mismatches"""
    logger.info("Fixing database schema issues...")
    
    os.makedirs(DATA_DIR, exist_ok=True)
    
    if not DB_PATH.exists():
        logger.info(f"No database at {DB_PATH}. It will be created during app startup.")
        return
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Fix activity_logs table (timestamp vs created_at)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='activity_logs'")
        if cursor.fetchone():
            cursor.execute('PRAGMA table_info(activity_logs)')
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'created_at' in columns and 'timestamp' not in columns:
                logger.info("Converting activity_logs.created_at to timestamp")
                # Create backup
                cursor.execute("CREATE TABLE activity_logs_backup AS SELECT * FROM activity_logs")
                # Drop original
                cursor.execute("DROP TABLE activity_logs")
                # Create new with correct schema
                cursor.execute("""
                CREATE TABLE activity_logs (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
                """)
                # Copy data back
                cursor.execute("""
                INSERT INTO activity_logs (id, user_id, action, timestamp, ip_address, user_agent)
                SELECT id, user_id, action, created_at, ip_address, user_agent FROM activity_logs_backup
                """)
                # Drop backup
                cursor.execute("DROP TABLE activity_logs_backup")
                conn.commit()
                logger.info("Fixed activity_logs table")
        
        # Fix stego_images table if needed
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='stego_images'")
        if cursor.fetchone():
            cursor.execute('PRAGMA table_info(stego_images)')
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'created_at' not in columns and 'timestamp' not in columns:
                logger.info("Adding missing timestamp to stego_images")
                cursor.execute("ALTER TABLE stego_images ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP")
                conn.commit()
        
        conn.close()
        logger.info("Database schema fixes completed")
    except Exception as e:
        logger.error(f"Database schema fix error: {e}")

def fix_template_routes():
    """Fix all incorrect URL endpoints in templates"""
    logger.info("Fixing template route issues...")
    
    patterns = [
        (r"url_for\(['\"]admin\.admin_dashboard['\"]", r"url_for('admin_bp.index'"),
        (r"url_for\(['\"]admin\.index['\"]", r"url_for('admin_bp.index'"),
        (r"url_for\(['\"]admin\.users['\"]", r"url_for('admin_bp.users'"),
        (r"url_for\(['\"]admin\.images['\"]", r"url_for('admin_bp.images'"),
        (r"url_for\(['\"]admin\.activity['\"]", r"url_for('admin_bp.activity'"),
        (r"url_for\(['\"]admin\.user_detail['\"]", r"url_for('admin_bp.user_detail'")
    ]
    
    # Counter for changes
    files_fixed = 0
    changes = 0
    
    # Process all template files
    for root, _, files in os.walk(TEMPLATE_DIR):
        for file in files:
            if file.endswith(('.html', '.j2')):
                file_path = os.path.join(root, file)
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                original = content
                
                # Apply all pattern fixes
                for pattern, replacement in patterns:
                    content = re.sub(pattern, replacement, content)
                
                # Fix the super() issue in dashboard.html
                if file == 'dashboard.html':
                    content = content.replace("{% if self.super() %}\n    {{ super() }}\n{% endif %}", "{{ super() }}")
                
                # Only write if changed
                if content != original:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    files_fixed += 1
                    logger.info(f"Fixed routes in: {file_path}")
    
    logger.info(f"Fixed templates in {files_fixed} files")

def add_missing_routes():
    """Add missing routes to admin_routes.py"""
    logger.info("Adding missing routes...")
    
    admin_routes_path = APP_DIR / "admin_routes.py"
    
    if admin_routes_path.exists():
        with open(admin_routes_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if user_detail route exists
        if "def user_detail" not in content:
            # Add the missing route before the last method
            route_code = """
@admin_bp.route('/users/<int:user_id>')
@admin_required
def user_detail(user_id):
    # Show detailed user information
    try:
        user = User.query.get_or_404(user_id)
        # Get user's images
        images = StegoImage.query.filter_by(user_id=user_id).all()
        # Get user's activity
        activities = ActivityLog.query.filter_by(user_id=user_id).order_by(ActivityLog.timestamp.desc()).all()
        
        return render_template('admin/user_detail.html', user=user, images=images, activities=activities)
    except Exception as e:
        logger.error(f"Error in admin user detail: {str(e)}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('admin_bp.users'))
"""
            # Insert before the last function
            if "@admin_bp.route('/status')" in content:
                content = content.replace("@admin_bp.route('/status')", f"{route_code}\n@admin_bp.route('/status')")
            else:
                content += route_code
                
            with open(admin_routes_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info("Added missing user_detail route")
    
    # Create the user_detail.html template if needed
    user_detail_template = TEMPLATE_DIR / "admin" / "user_detail.html"
    os.makedirs(TEMPLATE_DIR / "admin", exist_ok=True)
    
    if not user_detail_template.exists():
        with open(user_detail_template, 'w', encoding='utf-8') as f:
            f.write("""{% extends "base.html" %}

{% block title %}User Details - {{ user.username }}{% endblock %}

{% block content %}
<div class="container my-4">
    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="{{ url_for('admin_bp.index') }}">Admin</a></li>
            <li class="breadcrumb-item"><a href="{{ url_for('admin_bp.users') }}">Users</a></li>
            <li class="breadcrumb-item active">{{ user.username }}</li>
        </ol>
    </nav>
    
    <div class="card shadow-sm">
        <div class="card-header bg-primary text-white">
            <h2 class="mb-0">
                <i class="bi bi-person-fill me-2"></i>User Details
            </h2>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <h4>Basic Information</h4>
                    <table class="table">
                        <tr>
                            <th>Username:</th>
                            <td>{{ user.username }}</td>
                        </tr>
                        <tr>
                            <th>Email:</th>
                            <td>{{ user.email }}</td>
                        </tr>
                        <tr>
                            <th>Role:</th>
                            <td>
                                <span class="badge {% if user.role == 'admin' %}bg-danger{% else %}bg-success{% endif %}">
                                    {{ user.role|capitalize }}
                                </span>
                            </td>
                        </tr>
                        <tr>
                            <th>Phone:</th>
                            <td>{{ user.phone_number or 'Not provided' }}</td>
                        </tr>
                        <tr>
                            <th>Verified:</th>
                            <td>
                                {% if user.is_verified %}
                                    <span class="badge bg-success"><i class="bi bi-check-circle-fill me-1"></i>Yes</span>
                                {% else %}
                                    <span class="badge bg-warning"><i class="bi bi-exclamation-circle-fill me-1"></i>No</span>
                                {% endif %}
                            </td>
                        </tr>
                        <tr>
                            <th>Joined:</th>
                            <td>{{ user.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                        </tr>
                    </table>
                </div>
                
                <div class="col-md-6">
                    <h4>Usage Statistics</h4>
                    <div class="card mb-3">
                        <div class="card-body">
                            <h5 class="card-title">Images</h5>
                            <p class="card-text">Total images: {{ images|length }}</p>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">Activity</h5>
                            <p class="card-text">Total activity records: {{ activities|length }}</p>
                            <p class="card-text">Latest activity: 
                                {% if activities %}
                                    {{ activities[0].action }} ({{ activities[0].timestamp.strftime('%Y-%m-%d %H:%M') }})
                                {% else %}
                                    No activity recorded
                                {% endif %}
                            </p>
                        </div>
                    </div>
                </div>
            </div>
            
            <hr>
            
            <h4>Recent Activity</h4>
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Action</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for activity in activities[:10] %}
                        <tr>
                            <td>{{ activity.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                            <td>{{ activity.action }}</td>
                            <td>{{ activity.ip_address or 'Unknown' }}</td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="3" class="text-center">No activity records found</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        <div class="card-footer">
            <a href="{{ url_for('admin_bp.users') }}" class="btn btn-secondary">
                <i class="bi bi-arrow-left me-1"></i> Back to Users
            </a>
        </div>
    </div>
</div>
{% endblock %}
""")
        logger.info("Created user_detail.html template")

def fix_login_redirect():
    """Fix login redirection issues"""
    logger.info("Fixing login redirection...")
    
    app_path = APP_DIR / "app.py"
    
    with open(app_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if session handling is already fixed
    if "session.permanent = True" not in content:
        # Add session handling in login route
        login_success_pattern = r"if user and user\.check_password\(password\):\s+login_user\(user, remember=form\.remember\.data\)"
        login_success_replacement = """if user and user.check_password(password):
            login_user(user, remember=form.remember.data)
            
            # Force session creation and persistence
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            # Force session save
            session.modified = True"""
        
        content = re.sub(login_success_pattern, login_success_replacement, content)
        
        # Add the check-session route
        if "@app.route('/check-session')" not in content:
            check_session_route = """
@app.route('/check-session')
def check_session():
    \"\"\"Debug endpoint to check session status\"\"\"
    data = {
        'authenticated': current_user.is_authenticated,
        'session_data': {k: session.get(k) for k in session if k != '_flashes'},
        'user_info': None
    }
    
    if current_user.is_authenticated:
        data['user_info'] = {
            'id': current_user.id,
            'username': current_user.username,
            'role': current_user.role
        }
    
    return jsonify(data)
"""
            # Add before the last if __name__ == '__main__' block
            content = content.replace("if __name__ == '__main__':", f"{check_session_route}\nif __name__ == '__main__':")
        
        # Make sure session is imported
        if "from flask import" in content and ", session" not in content:
            content = content.replace("from flask import ", "from flask import session, ")
        
        with open(app_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info("Fixed login redirection issues")

def update_config_for_session():
    """Update config.py to improve session handling"""
    logger.info("Updating session configuration...")
    
    config_path = APP_DIR / "config.py"
    
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Add session configuration if not present
        if "SESSION_TYPE =" not in content:
            session_config = """
    # Session configuration
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)  # Extend to 7 days
    SESSION_COOKIE_SECURE = False  # Set to False for development
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # Use 'Lax' for login redirects to work
"""
            # Add to the Config class
            content = content.replace("class Config:", f"class Config:{session_config}")
            
            # Make sure datetime is imported
            if "from datetime import timedelta" not in content:
                if "import os" in content:
                    content = content.replace("import os", "import os\nfrom datetime import timedelta")
                else:
                    content = "from datetime import timedelta\n" + content
            
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info("Updated session configuration")

def add_js_helpers():
    """Add JavaScript helpers for better client-side behavior"""
    logger.info("Adding JavaScript helpers...")
    
    os.makedirs(STATIC_DIR / "js", exist_ok=True)
    
    # Update login_handler.js
    login_handler_path = STATIC_DIR / "js" / "login_handler.js"
    
    login_handler_content = """document.addEventListener('DOMContentLoaded', function() {
    console.log('Login handler script loaded');
    
    // Handle login form submission
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Logging in...';
            
            // Get CSRF token
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            
            // Send AJAX request
            fetch('/login', {
                method: 'POST',
                body: new FormData(this),
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'same-origin'
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || 'Login failed');
                    });
                }
                return response.json();
            })
            .then(data => {
                console.log('Login response:', data);
                
                if (data.success) {
                    // Display success message
                    if (typeof Swal !== 'undefined') {
                        Swal.fire({
                            icon: 'success',
                            title: 'Success!',
                            text: 'Login successful. Redirecting...',
                            timer: 1500,
                            showConfirmButton: false
                        });
                    }
                    
                    // First verify session is established before redirecting
                    verifyAndRedirect(data.redirect || '/dashboard');
                } else {
                    // Reset button
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                    
                    // Show error message
                    if (typeof Swal !== 'undefined') {
                        Swal.fire({
                            icon: 'error',
                            title: 'Login Failed',
                            text: data.message || 'Invalid username or password'
                        });
                    } else {
                        alert('Login failed: ' + (data.message || 'Invalid username or password'));
                    }
                }
            })
            .catch(error => {
                console.error('Login error:', error);
                
                // Reset button
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
                
                // Show error message
                if (typeof Swal !== 'undefined') {
                    Swal.fire({
                        icon: 'error',
                        title: 'Login Error',
                        text: error.message || 'An error occurred during login'
                    });
                } else {
                    alert('Login error: ' + (error.message || 'An error occurred'));
                }
            });
        });
    }
    
    // Function to verify session establishment before redirecting
    function verifyAndRedirect(url) {
        // Check if session is established
        fetch('/check-session', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            console.log('Session check:', data);
            
            if (data.authenticated) {
                // Session is established, redirect safely
                console.log('Session verified, redirecting to:', url);
                window.location.href = url;
            } else {
                // Session not established, use form submission as fallback
                console.log('Session not established, using fallback');
                if (document.getElementById('direct-login-form')) {
                    document.getElementById('direct-login-form').submit();
                } else {
                    // Last resort - reload page
                    window.location.reload();
                }
            }
        })
        .catch(error => {
            console.error('Session check error:', error);
            // Fallback to direct redirect
            window.location.href = url;
        });
    }
});
"""
    
    with open(login_handler_path, 'w', encoding='utf-8') as f:
        f.write(login_handler_content)
    logger.info("Created/updated login_handler.js")
    
    # Update dashboard_fallback.js
    dashboard_fallback_path = STATIC_DIR / "js" / "dashboard_fallback.js"
    
    dashboard_fallback_content = """document.addEventListener('DOMContentLoaded', function() {
    console.log("Dashboard fallback script loaded");
    
    // Handle the case where timestamp or created_at doesn't exist
    const fixDates = function() {
        const dateCells = document.querySelectorAll('.date-cell');
        dateCells.forEach(function(cell) {
            if (!cell) return;
            if (cell.textContent.includes('undefined') || cell.textContent.trim() === '') {
                cell.textContent = 'Unknown date';
                cell.classList.add('text-muted');
            }
        });
    };
    
    // Fix error when no images are found
    const fixEmptyImages = function() {
        const imagesTable = document.querySelector('#history-table, #images-table');
        const noImagesMsg = document.querySelector('#no-images-message');
        
        if (imagesTable && imagesTable.querySelector('tbody') && 
            imagesTable.querySelector('tbody').children.length === 0) {
            
            imagesTable.style.display = 'none';
            
            if (!noImagesMsg) {
                const container = document.querySelector('#images-container');
                if (container) {
                    const msgElement = document.createElement('div');
                    msgElement.id = 'no-images-message';
                    msgElement.className = 'text-center text-muted p-5';
                    msgElement.innerHTML = '<i class="bi bi-image" style="font-size: 3rem;"></i><p class="mt-3">You haven\\'t created any encrypted images yet.</p>';
                    container.appendChild(msgElement);
                }
            } else if (noImagesMsg) {
                noImagesMsg.style.display = 'block';
            }
        }
    };
    
    // Execute fixes
    try {
        fixDates();
        fixEmptyImages();
    } catch (err) {
        console.error("Error in dashboard fallback script:", err);
    }
});
"""
    
    with open(dashboard_fallback_path, 'w', encoding='utf-8') as f:
        f.write(dashboard_fallback_content)
    logger.info("Created/updated dashboard_fallback.js")

def run_all_fixes():
    """Run all fixes at once"""
    logger.info("Running all fixes...")
    
    try:
        # Create essential directories
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(STATIC_DIR / "js", exist_ok=True)
        os.makedirs(TEMPLATE_DIR / "admin", exist_ok=True)
        
        # Fix all issues
        fix_database_schema()
        fix_template_routes()
        add_missing_routes()
        fix_login_redirect()
        update_config_for_session()
        add_js_helpers()
        
        logger.info("")
        logger.info("=============================================")
        logger.info("ALL FIXES APPLIED SUCCESSFULLY!")
        logger.info("=============================================")
        logger.info("You can now run your app with:")
        logger.info("   flask run --host=0.0.0.0 --port=8080")
        logger.info("Or:")
        logger.info("   python app.py")
        logger.info("=============================================")
    except Exception as e:
        logger.error(f"Error running fixes: {e}")

if __name__ == "__main__":
    run_all_fixes()
