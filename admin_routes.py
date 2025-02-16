from flask import Blueprint, jsonify, request, flash, redirect, url_for, render_template
from flask_login import login_required, current_user
import logging

admin_bp = Blueprint('admin', __name__)

def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapped(*args, **kwargs):
        # Log current user's role for debugging
        user_role = getattr(current_user, 'role', 'None')
        logging.info(f"Current user role: {user_role}")
        if user_role != 'admin':
            flash("Access denied. Your role: " + user_role)
            return redirect(url_for("home"))
        return func(*args, **kwargs)
    return wrapped

@admin_bp.route('/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Retain the detailed logs view if needed
@admin_bp.route('/logs')
@login_required
@admin_required
def admin_logs():
    try:
        with open("app.log", "r", encoding="utf-8") as f:
            log_entries = f.readlines()
    except Exception as e:
        log_entries = ["Error reading log entries."]
    return render_template("admin_logs.html", logs=log_entries)

@admin_bp.route('/metrics', methods=['GET'])
@login_required
@admin_required
def metrics():
    try:
        from models import User  # Updated local import from models.py
        user_count = User.query.count()
    except Exception as e:
        logging.error(f"Error fetching users: {e}")
        return jsonify({'error': 'Failed to fetch user metrics'}), 500

    try:
        with open('app.log', 'r', encoding='utf-8') as f:
            log_count = len(f.readlines())
    except Exception as e:
        logging.error(f"Error reading app.log: {e}")
        log_count = 0

    return jsonify({'user_count': user_count, 'log_entries': log_count})

@admin_bp.route('/users', methods=['GET'])
@login_required
@admin_required
def list_users():
    try:
        from models import db, User
        users = User.query.all() or []
        users_data = [{'id': u.id, 'username': u.username, 'email': u.email, 'role': u.role} for u in users]
        return jsonify({'users': users_data})
    except Exception as e:
        logging.error(f"Error fetching user list: {e}")
        return jsonify({'error': 'Failed to fetch user list'}), 500

# GET: Render the user edit form.
@admin_bp.route('/users/<int:user_id>/edit', methods=['GET'])
@login_required
@admin_required
def edit_user(user_id):
    try:
        from models import db, User
        user = User.query.get_or_404(user_id)
        return render_template("edit_user.html", user=user)
    except Exception as e:
        logging.error(f"Error loading edit form for user {user_id}: {e}")
        flash("Failed to load edit form.", "danger")
        return redirect(url_for('admin.manage_users'))

# POST: Update user details based on form submission.
@admin_bp.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    try:
        from models import db, User
        user = User.query.get_or_404(user_id)
        data = request.form.to_dict()
        if 'role' in data:
            user.role = data['role']
        db.session.commit()
        flash(f"User {user.username} updated successfully.", "success")
    except Exception as e:
        from models import db
        db.session.rollback()
        logging.error(f"Error updating user {user_id}: {e}")
        flash("Error updating user. Please try again.", "danger")
    return redirect(url_for('admin.manage_users'))

# POST: Delete user.
@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        from models import db, User
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} deleted successfully.", "success")
    except Exception as e:
        from models import db
        db.session.rollback()
        logging.error(f"Error deleting user {user_id}: {e}")
        flash("Error deleting user. Please try again.", "danger")
    return redirect(url_for('admin.manage_users'))

# GET: Render manage users view.
@admin_bp.route('/users/manage', methods=['GET'])
@login_required
@admin_required
def manage_users():
    try:
        from models import db, User
        users = User.query.all()
        return render_template("admin_users.html", users=users)
    except Exception as e:
        logging.error(f"Error loading users list: {e}")
        flash("Unable to load users: " + str(e), "danger")
        return redirect(url_for("admin.admin_dashboard"))

# New: Generic role update for flexibility
@admin_bp.route('/users/<int:user_id>/set_role/<new_role>', methods=['GET'])
@login_required
@admin_required
def set_role(user_id, new_role):
    try:
        from models import db, User
        user = User.query.get_or_404(user_id)
        allowed_roles = ['user', 'moderator', 'admin']
        if new_role not in allowed_roles:
            flash("Invalid role.", "danger")
            return redirect(url_for('admin.manage_users'))
        user.role = new_role
        db.session.commit()
        flash(f"{user.username} set as {new_role}.", "success")
    except Exception as e:
        flash("Error updating role: " + str(e), "danger")
    return redirect(url_for('admin.manage_users'))

# Optionally, for clarity, add dedicated routes:
@admin_bp.route('/users/<int:user_id>/promote', methods=['GET'])
@login_required
@admin_required
def promote_user(user_id):
    try:
        from models import db, User
        user = User.query.get_or_404(user_id)
        user.role = 'admin'
        db.session.commit()
        flash(f"{user.username} promoted to admin.", "success")
    except Exception as e:
        flash("Error promoting user: " + str(e), "danger")
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/demote', methods=['GET'])
@login_required
@admin_required
def demote_user(user_id):
    try:
        from models import db, User
        user = User.query.get_or_404(user_id)
        user.role = 'user'
        db.session.commit()
        flash(f"{user.username} demoted to user.", "success")
    except Exception as e:
        flash("Error demoting user: " + str(e), "danger")
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/moderate', methods=['GET'])
@login_required
@admin_required
def moderate_user(user_id):
    try:
        from models import db, User
        user = User.query.get_or_404(user_id)
        user.role = 'moderator'
        db.session.commit()
        flash(f"{user.username} set as moderator.", "success")
    except Exception as e:
        flash("Error setting moderator role: " + str(e), "danger")
    return redirect(url_for('admin.manage_users'))
