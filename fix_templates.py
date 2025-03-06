#!/usr/bin/env python3
"""
Script to find and fix all template references to incorrect URL endpoints.
"""
import os
import re
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("FIX_TEMPLATES")

def fix_templates():
    """Find and fix all incorrect admin URL references in templates"""
    app_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = app_dir / "templates"
    
    # Counter for tracking changes
    changes_made = 0
    files_modified = 0
    
    # Patterns to fix
    patterns_to_replace = [
        (r"url_for\(['\"]admin\.admin_dashboard['\"]", r"url_for('admin_bp.index'"),
        (r"url_for\(['\"]admin\.index['\"]", r"url_for('admin_bp.index'"),
        (r"url_for\(['\"]admin\.users['\"]", r"url_for('admin_bp.users'"),
        (r"url_for\(['\"]admin\.images['\"]", r"url_for('admin_bp.images'"),
        (r"url_for\(['\"]admin\.activity['\"]", r"url_for('admin_bp.activity'"),
        # Add this new pattern to catch user_detail URLs
        (r"url_for\(['\"]admin\.user_detail['\"]", r"url_for('admin_bp.user_detail'"),
    ]
    
    # Walk through all template files
    for root, _, files in os.walk(templates_dir):
        for filename in files:
            if filename.endswith(('.html', '.j2')):
                file_path = os.path.join(root, filename)
                
                # Read file content
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                original_content = content
                file_changes = 0
                
                # Apply each pattern replacement
                for pattern, replacement in patterns_to_replace:
                    # Count matches for this pattern
                    matches = len(re.findall(pattern, content))
                    if matches > 0:
                        # Replace matches
                        content = re.sub(pattern, replacement, content)
                        file_changes += matches
                        logger.info(f"Found {matches} matches of {pattern} in {file_path}")
                
                # Only write to file if changes were made
                if content != original_content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    files_modified += 1
                    changes_made += file_changes
                    logger.info(f"Updated {file_path} with {file_changes} changes")
    
    logger.info(f"Fixed {changes_made} URL references across {files_modified} files")
    
    return changes_made, files_modified

if __name__ == "__main__":
    changes, files = fix_templates()
    
    if changes > 0:
        logger.info("Template fixes completed successfully!")
        logger.info(f"Made {changes} changes in {files} files")
    else:
        logger.info("No template issues found.")
