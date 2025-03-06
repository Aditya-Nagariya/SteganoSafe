"""
Admin routes for the SteganoSafe application.
"""
from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash, current_app, Response, send_file, send_from_directory, abort
from flask_login import login_required, current_user
from models import db, User, StegoImage, ActivityLog
import logging
import base64
from functools import wraps
import traceback
from datetime import datetime, timedelta
from sqlalchemy import func, desc, inspect, or_, and_
import sys
import os
import time
from io import BytesIO
from PIL import Image as PILImage

# Initialize blueprint
admin_bp = Blueprint('admin_bp', __name__)

# Decorator to require admin role
def admin_required(f):
    """Decorator to require admin role for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Admin access required", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(f):
    """Decorator to rate limit admin API requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Track request time in app config to avoid session dependency
        now = time.time()
        key = f"rate_limit_{request.endpoint}_user_{current_user.id}"
        last_request = getattr(current_app, key, None)
        
        if last_request and now - last_request < 0.5:  # 2 requests per second max
            return jsonify({'success': False, 'message': 'Rate limit exceeded'}), 429
            
        # Update last request time
        setattr(current_app, key, now)
        return f(*args, **kwargs)
    return decorated_function

# Dashboard routes
@admin_bp.route('/')
@login_required
@admin_required
def index():
    """Admin dashboard homepage"""
    user_count = User.query.count()
    image_count = StegoImage.query.count()
    activity_count = ActivityLog.query.count()
    
    # Get recent activities for dashboard
    recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    # Count verified users
    verified_users = User.query.filter_by(is_verified=True).count()
    
    return render_template(
        'admin/index.html',
        user_count=user_count,
        image_count=image_count,
        activity_count=activity_count,
        recent_activities=recent_activities,
        verified_users=verified_users
    )

# User management routes
@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """List all users"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/<int:user_id>')
@login_required
@admin_required
def user_detail(user_id):
    """View details for a specific user"""
    user = User.query.get_or_404(user_id)
    images = StegoImage.query.filter_by(user_id=user.id).all()
    activities = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc()).limit(50).all()
    
    return render_template(
        'admin/user_detail.html',
        user=user,
        images=images,
        activities=activities
    )

@admin_bp.route('/users/<int:user_id>/change-role/<string:role>', methods=['GET', 'POST'])
@login_required
@admin_required
def change_user_role(user_id, role):
    """Change a user's role"""
    if role not in ['admin', 'mod', 'user']:
        flash("Invalid role specified", "danger")
        return redirect(url_for('admin_bp.users'))
        
    user = User.query.get_or_404(user_id)
    
    # Don't let admins remove their own admin status
    if user.id == current_user.id and role != 'admin':
        flash("You cannot remove your own admin status", "danger")
        return redirect(url_for('admin_bp.users'))
    
    # Update role
    old_role = user.role
    user.role = role
    db.session.commit()
    
    # Log activity
    activity = ActivityLog(
        user_id=current_user.id,
        action=f"Changed user {user.username} role from {old_role} to {role}"
    )
    db.session.add(activity)
    db.session.commit()
    
    flash(f"User {user.username} role changed to {role}", "success")
    return redirect(url_for('admin_bp.users'))

@admin_bp.route('/users/<int:user_id>/verify', methods=['GET'])
@login_required
@admin_required
def verify_user(user_id):
    """Mark a user as verified"""
    user = User.query.get_or_404(user_id)
    
    user.is_verified = True
    db.session.commit()
    
    # Log activity
    activity = ActivityLog(
        user_id=current_user.id,
        action=f"Verified user {user.username}"
    )
    db.session.add(activity)
    db.session.commit()
    
    flash(f"User {user.username} has been verified", "success")
    return redirect(url_for('admin_bp.user_detail', user_id=user_id))

@admin_bp.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    """Update user details"""
    user = User.query.get_or_404(user_id)
    
    # Get form data
    username = request.form.get('username')
    email = request.form.get('email')
    phone_number = request.form.get('phone_number')
    role = request.form.get('role')
    is_verified = 'is_verified' in request.form
    
    # Update user
    if username and username != user.username:
        # Check if username is taken
        if User.query.filter(User.id != user_id, User.username == username).first():
            flash(f"Username '{username}' is already taken", "danger")
            return redirect(url_for('admin_bp.user_detail', user_id=user_id))
        user.username = username
        
    if email and email != user.email:
        # Check if email is taken
        if User.query.filter(User.id != user_id, User.email == email).first():
            flash(f"Email '{email}' is already registered", "danger")
            return redirect(url_for('admin_bp.user_detail', user_id=user_id))
        user.email = email
        
    user.phone_number = phone_number or None
    
    # Only update role if current user is admin
    if current_user.role == 'admin':
        # Don't let admin demote themselves
        if user.id == current_user.id and role != 'admin':
            flash("You cannot remove your own admin status", "danger")
        else:
            user.role = role
            
    user.is_verified = is_verified
        
    # Save changes
    db.session.commit()
    
    # Log activity
    activity = ActivityLog(
        user_id=current_user.id,
        action=f"Updated user {user.username}'s profile"
    )
    db.session.add(activity)
    db.session.commit()
        
    flash(f"User {user.username} updated successfully", "success")
    return redirect(url_for('admin_bp.user_detail', user_id=user_id))

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user"""
    user = User.query.get_or_404(user_id)
    
    # Don't let admins delete themselves
    if user.id == current_user.id:
        flash("You cannot delete your own account", "danger")
        return redirect(url_for('admin_bp.users'))
    
    # Log activity before deleting
    activity = ActivityLog(
        user_id=current_user.id,
        action=f"Deleted user {user.username} (ID: {user.id})"
    )
    db.session.add(activity)
    
    # Delete user's images
    images = StegoImage.query.filter_by(user_id=user.id).all()
    for image in images:
        db.session.delete(image)
    
    # Delete user's activity logs
    user_logs = ActivityLog.query.filter_by(user_id=user.id).all()
    for log in user_logs:
        db.session.delete(log)
    
    # Delete the user
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User {username} has been deleted", "success")
    return redirect(url_for('admin_bp.users'))

# Promote user to admin
@admin_bp.route('/users/<int:user_id>/promote', methods=['GET', 'POST'])
@login_required
@admin_required
def promote_user(user_id):
    """Promote a user to admin"""
    user = User.query.get_or_404(user_id)
    
    if user.role == 'admin':
        flash(f'{user.username} is already an admin', 'info')
    else:
        user.role = 'admin'
        db.session.commit()
        flash(f'{user.username} has been promoted to admin', 'success')
        
    return redirect(url_for('admin_bp.user_detail', user_id=user_id))

# Demote user to regular user
@admin_bp.route('/users/<int:user_id>/demote', methods=['GET', 'POST'])
@login_required
@admin_required
def demote_user(user_id):
    """Demote an admin to regular user"""
    user = User.query.get_or_404(user_id)
    
    # Don't allow demoting yourself
    if user.id == current_user.id:
        flash('You cannot demote yourself!', 'danger')
        return redirect(url_for('admin_bp.users'))
    
    if user.role != 'admin':
        flash(f'{user.username} is not an admin', 'info')
    else:
        user.role = 'user'
        db.session.commit()
        flash(f'{user.username} has been demoted to regular user', 'success')
        
    return redirect(url_for('admin_bp.user_detail', user_id=user_id))

# Image management routes
@admin_bp.route('/images')
@login_required
@admin_required
def images():
    """List all images with improved handling for missing image data"""
    try:
        logging.info("Admin images route called")
        
        # Get search and filter parameters
        search = request.args.get('search', '')
        sort_by = request.args.get('sort', 'id')
        order = request.args.get('order', 'desc')
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Build query with filters and sorting
        query = StegoImage.query
        
        # Add search filter if provided
        if search:
            query = query.filter(or_(
                StegoImage.original_filename.ilike(f'%{search}%'),
                StegoImage.encryption_type.ilike(f'%{search}%')
            ))
        
        # Add sorting
        if sort_by == 'filename':
            query = query.order_by(StegoImage.original_filename.desc() if order == 'desc' else StegoImage.original_filename)
        elif sort_by == 'user':
            query = query.order_by(StegoImage.user_id.desc() if order == 'desc' else StegoImage.user_id)
        elif sort_by == 'type':
            query = query.order_by(StegoImage.encryption_type.desc() if order == 'desc' else StegoImage.encryption_type)
        else:  # Default to id
            query = query.order_by(StegoImage.id.desc() if order == 'desc' else StegoImage.id)
        
        # Use pagination to avoid loading too many images at once
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        images = pagination.items
        
        # Create lightweight image data objects without full image_data
        image_list = []
        for img in images:
            # Create a preview URL instead of trying to load all image data
            preview_url = url_for('admin_bp.image_preview', image_id=img.id)
            
            # Get username
            username = "Unknown"
            try:
                user = User.query.get(img.user_id)
                if user:
                    username = user.username
            except Exception:
                pass
            
            image_list.append({
                'id': img.id,
                'user_id': img.user_id,
                'username': username,  # Add username for display
                'filename': img.filename,
                'original_filename': img.original_filename,
                'encryption_type': img.encryption_type or 'Unknown',
                'timestamp': img.timestamp if hasattr(img, 'timestamp') else None,
                'preview_url': preview_url,
                'has_image_data': img.image_data is not None
            })
        
        logging.info(f"Retrieved {len(image_list)} image records for page {page}")
        
        # Generate query parameters for pagination links
        query_params = {
            'search': search,
            'sort': sort_by,
            'order': order,
            'per_page': per_page
        }
        
        return render_template('admin/images.html', 
                              images=image_list,
                              pagination=pagination,
                              search=search,
                              sort=sort_by,
                              order=order,
                              query_params=query_params)
                              
    except Exception as e:
        logging.error(f"Error retrieving images: {str(e)}")
        logging.error(traceback.format_exc())
        flash("Error loading images: " + str(e), "danger")
        return redirect(url_for('admin_bp.index'))

@admin_bp.route('/image_preview/<int:image_id>')
@login_required
@admin_required
def image_preview(image_id):
    """Serve a preview of an image with improved error handling"""
    try:
        # Get the image from database
        image = StegoImage.query.get_or_404(image_id)
        
        # Check if image data exists
        if not image.image_data or len(image.image_data) == 0:
            logging.warning(f"No image data found for image ID {image_id}")
            # Return a placeholder image
            return send_file(os.path.join(current_app.root_path, 'static', 'img', 'placeholder.png'), mimetype='image/png')
            
        # Return the actual image data
        return Response(image.image_data, mimetype='image/png')
    except Exception as e:
        logging.error(f"Error serving image preview for ID {image_id}: {str(e)}")
        logging.error(traceback.format_exc())
        # Return a placeholder or error image
        return send_file(os.path.join(current_app.root_path, 'static', 'img', 'placeholder.png'), mimetype='image/png')

@admin_bp.route('/debug/image_preview/<int:image_id>')
@login_required
@admin_required
def debug_image_preview(image_id):
    """Debug endpoint to test image preview functionality"""
    try:
        # Get the image
        image = StegoImage.query.get_or_404(image_id)
        
        # Check if image data exists
        has_image_data = image.image_data is not None and len(image.image_data) > 0
        
        # Try to validate image format
        is_valid_image = False
        image_format = "unknown"
        img_size = "unknown"
        try:
            if has_image_data:
                from io import BytesIO
                img_io = BytesIO(image.image_data)
                pil_img = PILImage.open(img_io)
                image_format = pil_img.format
                img_size = pil_img.size
                is_valid_image = True
        except Exception as img_err:
            logging.error(f"Failed to validate image format: {str(img_err)}")
            image_format = f"Error: {str(img_err)}"
        
        # Get image info
        image_info = {
            'id': image.id,
            'filename': image.filename,
            'original_filename': image.original_filename,
            'encryption_type': image.encryption_type,
            'user_id': image.user_id,
            'has_image_data': has_image_data,
            'data_length': len(image.image_data) if has_image_data else 0,
            'preview_url': url_for('admin_bp.image_preview', image_id=image.id),
            'is_valid_image': is_valid_image,
            'image_format': image_format,
            'image_size': img_size,
            'direct_link': f"/admin/image_preview/{image.id}"
        }
        
        return jsonify(image_info)
    except Exception as e:
        logging.error(f"Debug image preview error: {str(e)}")
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@admin_bp.route('/create_placeholder')
@login_required
@admin_required
def create_placeholder():
    """Create a placeholder image if it doesn't exist"""
    try:
        placeholder_path = os.path.join(current_app.root_path, 'static', 'img', 'placeholder.png')
        
        if os.path.exists(placeholder_path):
            return jsonify({
                'success': True, 
                'message': 'Placeholder already exists',
                'path': placeholder_path
            })
            
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(placeholder_path), exist_ok=True)
        
        # Create a simple placeholder image
        from PIL import Image, ImageDraw
        img = Image.new('RGB', (80, 80), color=(233, 236, 239))
        draw = ImageDraw.Draw(img)
        
        # Draw border
        draw.rectangle([(0, 0), (79, 79)], outline=(173, 181, 189), width=1)
        
        # Draw a question mark (simple approximation since we don't want to deal with fonts)
        draw.ellipse([(30, 20), (50, 40)], outline=(108, 117, 125), width=2)
        draw.line([(40, 40), (40, 60)], fill=(108, 117, 125), width=2)
        draw.ellipse([(38, 62), (42, 66)], fill=(108, 117, 125))
        
        # Save the image
        img.save(placeholder_path)
        
        return jsonify({
            'success': True,
            'message': 'Created placeholder image',
            'path': placeholder_path
        })
    except Exception as e:
        logging.error(f"Error creating placeholder image: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@admin_bp.route('/fix_images')
@login_required
@admin_required
def fix_images():
    """Fix missing images in the database"""
    try:
        # Check for images with NULL image_data
        null_images = StegoImage.query.filter(StegoImage.image_data == None).all()
        
        # Check for empty image_data
        empty_images = StegoImage.query.filter(StegoImage.image_data != None).all()
        empty_images = [img for img in empty_images if len(img.image_data) == 0]
        
        # Create placeholder image data
        from PIL import Image, ImageDraw
        import io
        
        img = Image.new('RGB', (80, 80), color=(233, 236, 239))
        draw = ImageDraw.Draw(img)
        
        # Draw border
        draw.rectangle([(0, 0), (79, 79)], outline=(173, 181, 189), width=1)
        
        # Draw text
        draw.text((20, 30), "Missing", fill=(108, 117, 125))
        
        # Convert to bytes
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        placeholder_data = buf.getvalue()
        
        # Update all NULL images
        for img in null_images + empty_images:
            img.image_data = placeholder_data
            
        db.session.commit()
        
        return jsonify({
            'success': True,
            'null_images_fixed': len(null_images),
            'empty_images_fixed': len(empty_images),
            'total_fixed': len(null_images) + len(empty_images)
        })
    except Exception as e:
        logging.error(f"Error fixing images: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@admin_bp.route('/diagnose_images')
@login_required
@admin_required
def diagnose_images():
    """Diagnose issues with images in the admin panel"""
    try:
        # Get count of images
        image_count = StegoImage.query.count()
        
        # Get sample images (first 5)
        sample_images = StegoImage.query.limit(5).all()
        
        # Check image data
        image_diagnostics = []
        for img in sample_images:
            # Basic info
            img_info = {
                'id': img.id,
                'filename': img.filename,
                'original_filename': img.original_filename,
                'user_id': img.user_id,
                'preview_url': url_for('admin_bp.image_preview', image_id=img.id)
            }
            
            # Check image data
            if img.image_data is None:
                img_info['status'] = 'null_data'
                img_info['data_length'] = 0
            elif len(img.image_data) == 0:
                img_info['status'] = 'empty_data'
                img_info['data_length'] = 0
            else:
                img_info['status'] = 'has_data'
                img_info['data_length'] = len(img.image_data)
                
                # Try to validate image format
                try:
                    from io import BytesIO
                    img_io = BytesIO(img.image_data)
                    pil_img = PILImage.open(img_io)
                    img_info['format'] = pil_img.format
                    img_info['size'] = pil_img.size
                    img_info['mode'] = pil_img.mode
                    img_info['valid'] = True
                except Exception as img_err:
                    img_info['valid'] = False
                    img_info['error'] = str(img_err)
            
            image_diagnostics.append(img_info)
            
        # Check template existence
        template_path = os.path.join(current_app.root_path, 'templates', 'admin', 'images.html')
        template_exists = os.path.exists(template_path)
        
        # Check placeholder existence
        placeholder_path = os.path.join(current_app.root_path, 'static', 'img', 'placeholder.png')
        placeholder_exists = os.path.exists(placeholder_path)
        
        return jsonify({
            'image_count': image_count,
            'sample_images': image_diagnostics,
            'template_exists': template_exists,
            'template_path': template_path,
            'placeholder_exists': placeholder_exists,
            'placeholder_path': placeholder_path,
            'static_url_path': current_app.static_url_path,
            'test_image_url': url_for('admin_bp.image_preview', image_id=sample_images[0].id if sample_images else 0)
        })
    except Exception as e:
        logging.error(f"Diagnostics error: {str(e)}")
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@admin_bp.route('/debug/images')
@login_required
@admin_required
def debug_images():
    """Debug endpoint to check what's in the image table"""
    try:
        # Get table info
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Check if stego_images table exists
        table_exists = 'stego_images' in tables
        
        # Get columns if table exists
        columns = []
        if table_exists:
            columns = [c['name'] for c in inspector.get_columns('stego_images')]
            
        # Try count query
        count = 0
        try:
            count = db.session.query(func.count(StegoImage.id)).scalar()
        except Exception as count_error:
            count = f"Error counting: {str(count_error)}"
            
        # Try raw SQL
        raw_results = []
        try:
            raw_query = "SELECT id, user_id, filename, original_filename FROM stego_images LIMIT 5"
            raw_results = db.session.execute(raw_query).fetchall()
        except Exception as sql_error:
            raw_results = [f"SQL Error: {str(sql_error)}"]
            
        return jsonify({
            'database_ok': True,
            'tables': tables,
            'stego_images_table_exists': table_exists,
            'stego_images_columns': columns,
            'image_count': count,
            'sample_images': [dict(zip(['id', 'user_id', 'filename', 'original_filename'], row)) 
                              for row in raw_results] if raw_results and isinstance(raw_results, list) else raw_results
        })
    except Exception as e:
        return jsonify({
            'database_ok': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@admin_bp.route('/export/users')
@login_required
@admin_required
def export_users():
    """Export users data as CSV"""
    import csv
    from io import StringIO
    
    try:
        users = User.query.all()
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Username', 'Email', 'Phone', 'Role', 'Verified', 'Created At'])
        
        # Write user data
        for user in users:
            created_at = user.created_at.strftime('%Y-%m-%d %H:%M:%S') if hasattr(user, 'created_at') else 'N/A'
            writer.writerow([
                user.id,
                user.username,
                user.email,
                user.phone_number or 'N/A',
                user.role,
                'Yes' if user.is_verified else 'No',
                created_at
            ])
        
        # Create response
        output.seek(0)
        
        # Log activity
        activity = ActivityLog(
            user_id=current_user.id,
            action=f"Exported users data"
        )
        db.session.add(activity)
        db.session.commit()
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=users.csv'}
        )
        
    except Exception as e:
        logging.error(f"Error exporting users: {str(e)}")
        flash(f"Error exporting users: {str(e)}", "danger")
        return redirect(url_for('admin_bp.users'))

@admin_bp.route('/export/logs')
@login_required
@admin_required
def export_logs():
    """Export activity logs as CSV"""
    import csv
    from io import StringIO
    
    try:
        # Get logs with user information
        logs = db.session.query(
            ActivityLog, User.username
        ).outerjoin(
            User, ActivityLog.user_id == User.id
        ).order_by(
            ActivityLog.timestamp.desc()
        ).all()
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Timestamp', 'User ID', 'Username', 'Action', 'IP Address'])
        
        # Write log data
        for log, username in logs:
            writer.writerow([
                log.id,
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.user_id,
                username or 'Unknown',
                log.action,
                log.ip_address or 'N/A'
            ])
        
        # Create response
        output.seek(0)
        
        # Log activity
        activity = ActivityLog(
            user_id=current_user.id,
            action=f"Exported activity logs"
        )
        db.session.add(activity)
        db.session.commit()
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=activity_logs.csv'}
        )
        
    except Exception as e:
        logging.error(f"Error exporting logs: {str(e)}")
        flash(f"Error exporting logs: {str(e)}", "danger")
        return redirect(url_for('admin_bp.activity'))

# Settings route
@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    """View and update application settings"""
    from stego import AVAILABLE_ENCRYPTION_METHODS
    
    if request.method == 'POST':
        default_method = request.form.get('default_encryption_method')
        if default_method in AVAILABLE_ENCRYPTION_METHODS:
            # Save to database or config
            from config import update_config
            update_config('DEFAULT_ENCRYPTION_METHOD', default_method)
            flash(f'Default encryption method set to: {default_method}', 'success')
        return redirect(url_for('admin_bp.settings'))
    
    # Get current default method from config
    from config import Config
    current_default = getattr(Config, 'DEFAULT_ENCRYPTION_METHOD', 'LSB')
    
    return render_template(
        'admin/settings.html', 
        encryption_methods=AVAILABLE_ENCRYPTION_METHODS,
        current_default=current_default
    )

@admin_bp.route('/system-info')
@login_required
@admin_required
def system_info():
    """View system information"""
    import platform
    import sys
    import os
    import psutil
    
    try:
        # System info
        system_data = {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node()
        }
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_data = {
            'total': f"{memory.total / (1024 ** 3):.2f} GB",
            'available': f"{memory.available / (1024 ** 3):.2f} GB",
            'used': f"{memory.used / (1024 ** 3):.2f} GB",
            'percent': f"{memory.percent}%"
        }
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_data = {
            'total': f"{disk.total / (1024 ** 3):.2f} GB",
            'used': f"{disk.used / (1024 ** 3):.2f} GB",
            'free': f"{disk.free / (1024 ** 3):.2f} GB",
            'percent': f"{disk.percent}%"
        }
        
        # CPU info
        cpu_data = {
            'cores_physical': psutil.cpu_count(logical=False),
            'cores_logical': psutil.cpu_count(logical=True),
            'usage_percent': psutil.cpu_percent(interval=1)
        }
        
        # App info
        app_data = {
            'debug': current_app.debug,
            'testing': current_app.testing,
            'secret_key_set': bool(current_app.secret_key),
            'database_uri': current_app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set').split('://')[0]
        }
        
        return render_template(
            'admin/system_info.html',
            system=system_data,
            memory=memory_data,
            disk=disk_data,
            cpu=cpu_data,
            app=app_data
        )
    except Exception as e:
        logging.error(f"Error getting system info: {str(e)}")
        flash(f"Error getting system info: {str(e)}", "danger")
        return redirect(url_for('admin_bp.index'))

@admin_bp.route('/activity')
@login_required
@admin_required
def activity():
    """View activity logs"""
    # Get filter and pagination parameters
    user_id = request.args.get('user_id', type=int)
    action_type = request.args.get('action_type', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Build query
    query = ActivityLog.query.order_by(ActivityLog.timestamp.desc())
    
    # Apply filters
    if user_id:
        query = query.filter(ActivityLog.user_id == user_id)
    if action_type:
        query = query.filter(ActivityLog.action.like(f'%{action_type}%'))
    
    # Get total count for stats before pagination
    total_logs = query.count()
    
    # Paginate results
    logs = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get users for filter dropdown
    users = User.query.all()
    
    # Get action types from recent logs
    action_types = []
    try:
        action_samples = db.session.query(ActivityLog.action).distinct().limit(100).all()
        for action in action_samples:
            # Extract the first word as action type
            parts = action[0].split()
            if parts:
                action_type = parts[0]
                if action_type not in action_types:
                    action_types.append(action_type)
    except Exception as e:
        logging.error(f"Error getting action types: {e}")
    
    return render_template(
        'admin/activity.html', 
        logs=logs,
        total_logs=total_logs,  # Pass the total count separately
        users=users,
        action_types=sorted(action_types),
        selected_user=user_id,
        selected_action=action_type
    )

@admin_bp.route('/analytics')
@login_required
@admin_required
def analytics():
    """View analytics dashboard"""
    try:
        # Get filter parameters
        time_period = request.args.get('period', '7') # Default to 7 days
        
        return render_template(
            'admin/analytics.html',
            time_period=time_period
        )
    except Exception as e:
        logging.error(f"Error rendering analytics: {str(e)}")
        logging.error(traceback.format_exc())
        return f"Error loading analytics: {str(e)}", 500

@admin_bp.route('/backup')
@login_required
@admin_required
def backup_database():
    """Backup the database"""
    try:
        from datetime import datetime
        import os
        import shutil
        from config import Config
        # Get database path from config
        db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
        # Check if it's a SQLite database (file-based)
        if db_uri.startswith('sqlite:///'):
            # Extract the path
            db_path = db_uri.replace('sqlite:///', '')
            if os.path.exists(db_path):
                # Create backup directory if needed
                backup_dir = os.path.join(current_app.root_path, 'backups')
                os.makedirs(backup_dir, exist_ok=True)
                # Create backup filename with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_filename = f"backup_{timestamp}.db"
                backup_path = os.path.join(backup_dir, backup_filename)
                # Copy the database file
                shutil.copy2(db_path, backup_path)
                # Log the activity
                activity = ActivityLog(
                    user_id=current_user.id,
                    action=f"Created database backup: {backup_filename}"
                )
                db.session.add(activity)
                db.session.commit()
                flash(f"Database backup created successfully: {backup_filename}", "success")
                return redirect(url_for('admin_bp.index'))
            else:
                flash("Database file not found", "danger")
                return redirect(url_for('admin_bp.index'))
        else:
            flash("Backup only supported for SQLite databases", "warning")
            return redirect(url_for('admin_bp.index'))
    except Exception as e:
        logging.error(f"Backup error: {str(e)}")
        flash(f"Error creating backup: {str(e)}", "danger")
        return redirect(url_for('admin_bp.index'))

@admin_bp.route('/restore', methods=['GET', 'POST'])
@login_required
@admin_required
def restore_database():
    """Restore database from backup"""
    if request.method == 'POST':
        try:
            backup_file = request.form.get('backup_file')
            
            if not backup_file:
                flash("No backup file selected", "danger")
                return redirect(url_for('admin_bp.restore_database'))
            
            # Get database path from config
            db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
            # Check if it's a SQLite database (file-based)
            if db_uri.startswith('sqlite:///'):
                # Extract the path
                db_path = db_uri.replace('sqlite:///', '')
                
                # Validate backup file path
                backup_dir = os.path.join(current_app.root_path, 'backups')
                backup_path = os.path.join(backup_dir, backup_file)
                
                if not os.path.exists(backup_path):
                    flash("Backup file not found", "danger")
                    return redirect(url_for('admin_bp.restore_database'))
                
                # Create a backup of the current database first
                import shutil
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                pre_restore_backup = os.path.join(backup_dir, f"pre_restore_{timestamp}.db")
                shutil.copy2(db_path, pre_restore_backup)
                
                # Restore by copying the backup file to the database location
                shutil.copy2(backup_path, db_path)
                
                # Log the activity (this needs to be after the restore since the database was replaced)
                activity = ActivityLog(
                    user_id=current_user.id,
                    action=f"Restored database from backup: {backup_file}"
                )
                db.session.add(activity)
                try:
                    db.session.commit()
                except Exception:
                    # If we can't log to the restored database, that's ok
                    db.session.rollback()
                flash(f"Database restored successfully from {backup_file}", "success")
                return redirect(url_for('admin_bp.index'))
            else:
                flash("Restore only supported for SQLite databases", "warning")
                return redirect(url_for('admin_bp.index'))
        except Exception as e:
            logging.error(f"Restore error: {str(e)}")
            flash(f"Error restoring database: {str(e)}", "danger")
            return redirect(url_for('admin_bp.restore_database'))
    # GET request - show restore form
    try:
        # List available backups
        backup_dir = os.path.join(current_app.root_path, 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        backups = []
        for file in os.listdir(backup_dir):
            if file.endswith('.db') and os.path.isfile(os.path.join(backup_dir, file)):
                file_stat = os.stat(os.path.join(backup_dir, file))
                backups.append({
                    'filename': file,
                    'size': file_stat.st_size,
                    'created': datetime.fromtimestamp(file_stat.st_ctime)
                })
        # Sort by creation date, newest first
        backups.sort(key=lambda x: x['created'], reverse=True)
        return render_template('admin/restore.html', backups=backups)
    except Exception as e:
        logging.error(f"Error listing backups: {str(e)}")
        flash(f"Error listing backups: {str(e)}", "danger")
        return redirect(url_for('admin_bp.index'))

@admin_bp.route('/view-logs')
@login_required
@admin_required
def view_logs():
    """View application logs"""
    try:
        log_path = os.path.join(current_app.root_path, 'app.log')
        
        if not os.path.exists(log_path):
            flash("Log file not found", "warning")
            return render_template('admin/logs.html', logs=["No logs available"])
        
        # Get the last N lines of the log file
        max_lines = request.args.get('lines', 500, type=int)
        
        # Read the log file
        with open(log_path, 'r') as f:
            # Read all lines but keep only the last N
            all_lines = f.readlines()
            logs = all_lines[-max_lines:] if len(all_lines) > max_lines else all_lines
        
        return render_template('admin/logs.html', logs=logs, log_count=len(logs), max_lines=max_lines)
    except Exception as e:
        logging.error(f"Error reading logs: {str(e)}")
        flash(f"Error reading logs: {str(e)}", "danger")
        return render_template('admin/logs.html', logs=[f"Error: {str(e)}"])

@admin_bp.route('/clear-logs', methods=['POST'])
@login_required
@admin_required
def clear_logs():
    """Clear application logs"""
    try:
        log_path = os.path.join(current_app.root_path, 'app.log')
        
        if os.path.exists(log_path):
            # Backup the current log
            backup_dir = os.path.join(current_app.root_path, 'logs_backup')
            os.makedirs(backup_dir, exist_ok=True)
            # Create backup filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(backup_dir, f"app_log_backup_{timestamp}.log")
            
            # Copy the log file
            import shutil
            shutil.copy2(log_path, backup_path)
            
            # Clear the log file
            with open(log_path, 'w') as f:
                f.write(f"Log cleared by {current_user.username} at {datetime.now()}\n")
            
            # Log the activity
            activity = ActivityLog(
                user_id=current_user.id,
                action="Cleared application logs"
            )
            db.session.add(activity)
            db.session.commit()
            flash("Logs cleared successfully", "success")
        else:
            flash("Log file not found", "warning")
            
        return redirect(url_for('admin_bp.view_logs'))
    except Exception as e:
        logging.error(f"Error clearing logs: {str(e)}")
        flash(f"Error clearing logs: {str(e)}", "danger")
        return redirect(url_for('admin_bp.view_logs'))

# Rename the second debug_images route to fix the conflict
@admin_bp.route('/debug/db-images')
@login_required
@admin_required
def debug_db_images():
    """Debug endpoint to check what's in the image table database"""
    try:
        # Get table info
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Check if stego_images table exists
        table_exists = 'stego_images' in tables
        
        # Get columns if table exists
        columns = []
        if table_exists:
            columns = [c['name'] for c in inspector.get_columns('stego_images')]
            
        # Try count query
        count = 0
        try:
            count = db.session.query(func.count(StegoImage.id)).scalar()
        except Exception as count_error:
            count = f"Error counting: {str(count_error)}"
            
        # Try raw SQL
        raw_results = []
        try:
            raw_query = "SELECT id, user_id, filename, original_filename FROM stego_images LIMIT 5"
            raw_results = db.session.execute(raw_query).fetchall()
        except Exception as sql_error:
            raw_results = [f"SQL Error: {str(sql_error)}"]
            
        return jsonify({
            'database_ok': True,
            'tables': tables,
            'stego_images_table_exists': table_exists,
            'stego_images_columns': columns,
            'image_count': count,
            'sample_images': [dict(zip(['id', 'user_id', 'filename', 'original_filename'], row)) 
                             for row in raw_results] if raw_results and isinstance(raw_results, list) else raw_results
        })
    except Exception as e:
        return jsonify({
            'database_ok': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@admin_bp.route('/api/stats')
@login_required
@admin_required
def get_stats():
    """API endpoint to get dashboard stats"""
    week_ago = datetime.utcnow() - timedelta(days=7)
    
    # User stats
    total_users = User.query.count()
    new_users = User.query.filter(User.created_at >= week_ago).count() if hasattr(User, 'created_at') else 0
    
    # Image stats
    total_images = StegoImage.query.count()
    new_images = StegoImage.query.filter(StegoImage.created_at >= week_ago).count() if hasattr(StegoImage, 'created_at') else 0
    
    # Encryption method distribution
    encryption_methods = db.session.query(
        StegoImage.encryption_type, 
        func.count(StegoImage.id).label('count')
    ).group_by(StegoImage.encryption_type).all()
    
    return jsonify({
        'users': {
            'total': total_users,
            'new': new_users,
        },
        'images': {
            'total': total_images,
            'new': new_images
        },
        'encryption_methods': {
            method[0] or 'Unknown': method[1] for method in encryption_methods
        }
    })

# Add API stats endpoint for settings page
@admin_bp.route('/api_stats')
@login_required
@admin_required
def api_stats():
    """API endpoint to get stats for the settings page"""
    return get_stats()  # Reuse the get_stats function logic

@admin_bp.route('/api/analytics/summary')
@login_required
@admin_required
def analytics_summary():
    """API endpoint for analytics summary data"""
    try:
        # Get the requested time period from the query parameters (default: 7 days)
        days = int(request.args.get('days', '7'))
        
        # Time periods for comparison
        now = datetime.now()
        last_x_days = now - timedelta(days=days)
        last_x_days_2x = now - timedelta(days=days*2)  # Previous period of the same length
        
        # User metrics
        total_users = User.query.count()
        new_users_period = User.query.filter(User.created_at >= last_x_days).count()
        new_users_prev = User.query.filter(
            User.created_at >= last_x_days_2x,
            User.created_at < last_x_days
        ).count()
        verified_users = User.query.filter_by(is_verified=True).count()
        
        # Activity metrics
        encryptions_period = ActivityLog.query.filter(
            ActivityLog.timestamp >= last_x_days,
            ActivityLog.action.like('%Encrypted%')
        ).count()
        encryptions_prev = ActivityLog.query.filter(
            ActivityLog.timestamp >= last_x_days_2x,
            ActivityLog.timestamp < last_x_days,
            ActivityLog.action.like('%Encrypted%')
        ).count()
        
        decryptions_period = ActivityLog.query.filter(
            ActivityLog.timestamp >= last_x_days,
            ActivityLog.action.like('%decrypted%')
        ).count()
        decryptions_prev = ActivityLog.query.filter(
            ActivityLog.timestamp >= last_x_days_2x,
            ActivityLog.timestamp < last_x_days,
            ActivityLog.action.like('%decrypted%')
        ).count()
        
        # Active users
        active_users = db.session.query(func.distinct(ActivityLog.user_id))\
            .filter(ActivityLog.timestamp >= last_x_days).count()
        
        active_users_prev = db.session.query(func.distinct(ActivityLog.user_id))\
            .filter(
                ActivityLog.timestamp >= last_x_days_2x,
                ActivityLog.timestamp < last_x_days
            ).count()
        
        # Calculate trend percentages
        def calc_trend(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)
            
        user_trend = calc_trend(new_users_period, new_users_prev)
        encryption_trend = calc_trend(encryptions_period, encryptions_prev)
        decryption_trend = calc_trend(decryptions_period, decryptions_prev)
        active_trend = calc_trend(active_users, active_users_prev)
        
        # Get top users with their activity counts
        top_users = db.session.query(
            User.id,
            User.username,
            func.count(ActivityLog.id).label('activity_count')
        ).join(ActivityLog, User.id == ActivityLog.user_id)\
         .filter(ActivityLog.timestamp >= last_x_days)\
         .group_by(User.id)\
         .order_by(desc('activity_count'))\
         .limit(5).all()
        
        top_users_data = []
        for user in top_users:
            # Get a breakdown of user activities
            user_encryptions = ActivityLog.query.filter(
                ActivityLog.user_id == user.id,
                ActivityLog.timestamp >= last_x_days,
                ActivityLog.action.like('%Encrypted%')
            ).count()
            
            user_decryptions = ActivityLog.query.filter(
                ActivityLog.user_id == user.id,
                ActivityLog.timestamp >= last_x_days,
                ActivityLog.action.like('%decrypted%')
            ).count()
            
            # Get user's last activity timestamp
            last_activity = ActivityLog.query.filter(
                ActivityLog.user_id == user.id
            ).order_by(ActivityLog.timestamp.desc()).first()
            
            last_active = 'Unknown'
            if last_activity:
                # Format last active as relative time
                time_diff = datetime.now() - last_activity.timestamp
                if time_diff.days == 0:
                    # Today - show hours
                    hours = time_diff.seconds // 3600
                    if hours == 0:
                        last_active = 'Just now'
                    else:
                        last_active = f"{hours}h ago"
                elif time_diff.days == 1:
                    last_active = 'Yesterday'
                else:
                    last_active = f"{time_diff.days}d ago"
                    
            top_users_data.append({
                'id': user.id,
                'username': user.username,
                'activity_count': user.activity_count,
                'initials': user.username[0:2].upper() if user.username else 'UN',
                'encryptions': user_encryptions,
                'decryptions': user_decryptions,
                'last_active': last_active
            })
        
        # Daily activity data
        daily_activity = []
        
        # Determine how many days to show based on the requested period
        days_to_show = min(days, 30)  # Cap at 30 days to avoid making the chart too cluttered
        
        for i in range(days_to_show):
            day = now - timedelta(days=(days_to_show-1-i))  # Start from the oldest day
            next_day = day + timedelta(days=1)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = next_day.replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Count activities on this day
            encryptions = ActivityLog.query.filter(
                ActivityLog.timestamp >= day_start,
                ActivityLog.timestamp < day_end,
                ActivityLog.action.like('%Encrypted%')
            ).count()
            
            decryptions = ActivityLog.query.filter(
                ActivityLog.timestamp >= day_start,
                ActivityLog.timestamp < day_end,
                ActivityLog.action.like('%decrypted%')
            ).count()
            
            daily_activity.append({
                'date': day_start.strftime('%Y-%m-%d'),
                'label': day_start.strftime('%b %d'),
                'encryptions': encryptions,
                'decryptions': decryptions,
                'total': encryptions + decryptions
            })
        
        # Return all the collected data
        return jsonify({
            'success': True,
            'days': days,
            'summary': {
                'total_users': total_users,
                'verified_users': verified_users,
                'new_users': new_users_period,
                'new_users_trend': user_trend,
                'encryptions': encryptions_period,
                'encryptions_trend': encryption_trend,
                'decryptions': decryptions_period,
                'decryptions_trend': decryption_trend,
                'active_users': active_users,
                'active_users_trend': active_trend
            },
            'top_users': top_users_data,
            'daily_activity': daily_activity,
            'method_counts': {
                'LSB': ActivityLog.query.filter(ActivityLog.action.like('%LSB%')).count(),
                'DCT': ActivityLog.query.filter(ActivityLog.action.like('%DCT%')).count(),
                'PVD': ActivityLog.query.filter(ActivityLog.action.like('%PVD%')).count(),
                'DWT': ActivityLog.query.filter(ActivityLog.action.like('%DWT%')).count()
            }
        })
    except Exception as e:
        logging.error(f"Analytics error: {str(e)}")
        logging.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e),
            'trace': traceback.format_exc() if current_app.debug else 'Error processing analytics data'
        }), 500

# Add the missing bulk delete images route
@admin_bp.route('/images/bulk-delete', methods=['POST'])
@login_required
@admin_required
def bulk_delete_images():
    """Bulk delete images based on criteria"""
    try:
        delete_type = request.form.get('delete_type')
        if not delete_type:
            flash("No deletion criteria specified", "danger")
            return redirect(url_for('admin_bp.images'))
        
        # Confirm checkbox required
        if 'confirm_delete' not in request.form:
            flash("You must confirm the deletion", "danger")
            return redirect(url_for('admin_bp.images'))
        
        # Base query
        query = StegoImage.query
        
        # Apply filter based on delete_type
        if delete_type == 'all':
            # Get all images
            pass  # No additional filter needed
        elif delete_type == 'user':
            user_id = request.form.get('user_id', type=int)
            if not user_id:
                flash("No user selected", "danger")
                return redirect(url_for('admin_bp.images'))
            query = query.filter(StegoImage.user_id == user_id)
        elif delete_type == 'encryption_type':
            encryption_type = request.form.get('encryption_type')
            if not encryption_type:
                flash("No encryption type selected", "danger")
                return redirect(url_for('admin_bp.images'))
            query = query.filter(StegoImage.encryption_type == encryption_type)
        elif delete_type == 'older_than':
            older_than_date = request.form.get('older_than_date')
            if not older_than_date:
                flash("No date selected", "danger")
                return redirect(url_for('admin_bp.images'))
            # Convert to datetime
            try:
                older_than_datetime = datetime.strptime(older_than_date, '%Y-%m-%d')
                query = query.filter(StegoImage.timestamp < older_than_datetime)
            except ValueError:
                flash("Invalid date format", "danger")
                return redirect(url_for('admin_bp.images'))
        else:
            flash("Invalid deletion criteria", "danger")
            return redirect(url_for('admin_bp.images'))
            
        # Get images to delete
        images_to_delete = query.all()
        count = len(images_to_delete)
        
        if count == 0:
            flash("No images found matching the criteria", "warning")
            return redirect(url_for('admin_bp.images'))
            
        # Delete the images
        for image in images_to_delete:
            db.session.delete(image)
        
        # Log the activity
        activity = ActivityLog(
            user_id=current_user.id,
            action=f"Bulk deleted {count} images with criteria: {delete_type}"
        )
        db.session.add(activity)
        db.session.commit()
        
        flash(f"Successfully deleted {count} images", "success")
        return redirect(url_for('admin_bp.images'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Bulk delete error: {str(e)}")
        logging.error(traceback.format_exc())
        flash(f"Error deleting images: {str(e)}", "danger")
        return redirect(url_for('admin_bp.images'))

@admin_bp.route('/images/<int:image_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_image(image_id):
    """Delete an individual image"""
    try:
        image = StegoImage.query.get_or_404(image_id)
        
        # Store image info for activity log
        image_filename = image.original_filename
        
        # Delete the image
        db.session.delete(image)
        
        # Log the activity
        activity = ActivityLog(
            user_id=current_user.id,
            action=f"Deleted image: {image_filename} (ID: {image_id})"
        )
        db.session.add(activity)
        db.session.commit()
        
        flash(f"Image '{image_filename}' deleted successfully", "success")
        return redirect(url_for('admin_bp.images'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting image ID {image_id}: {str(e)}")
        logging.error(traceback.format_exc())
        flash(f"Error deleting image: {str(e)}", "danger")
        return redirect(url_for('admin_bp.images'))

@admin_bp.route('/api/users')
@login_required
@admin_required
def api_users():
    """API endpoint to get user list for UI components"""
    try:
        users = User.query.all()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email
            })
        
        return jsonify({
            'success': True,
            'users': user_list
        })
    except Exception as e:
        logging.error(f"Error getting users for API: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
