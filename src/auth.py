#!/usr/bin/env python3
"""
Authentication module for the System Monitor Web Dashboard.
Handles user authentication, roles, and permissions.
"""

import os
import json
import hashlib
from functools import wraps
from flask import session, request, redirect, url_for, flash
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user

# User roles
ADMIN_ROLE = 'admin'
VIEWER_ROLE = 'viewer'

class User(UserMixin):
    """User model for authentication."""
    
    def __init__(self, username, password_hash, role):
        self.id = username
        self.username = username
        self.password_hash = password_hash
        self.role = role
    
    def is_admin(self):
        """Check if user is an admin."""
        return self.role == ADMIN_ROLE
    
    def is_viewer(self):
        """Check if user is a viewer."""
        return self.role == VIEWER_ROLE
    
    def can_edit(self):
        """Check if user can edit (only admins can edit)."""
        return self.is_admin()

class AuthManager:
    """Manages user authentication and authorization."""
    
    def __init__(self, users_file='users.json'):
        self.users_file = users_file
        self.users = {}
        self.load_users()
    
    def load_users(self):
        """Load users from JSON file."""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    data = json.load(f)
                    for username, user_data in data.items():
                        self.users[username] = User(
                            username=username,
                            password_hash=user_data['password_hash'],
                            role=user_data['role']
                        )
            except Exception as e:
                print(f"Error loading users: {e}")
                # Create default admin user if file doesn't exist or is corrupted
                self.create_default_users()
        else:
            # Create default users if file doesn't exist
            self.create_default_users()
    
    def create_default_users(self):
        """Create default admin and viewer users."""
        # Default admin: admin/admin123
        admin_hash = self.hash_password('admin123')
        self.users['admin'] = User('admin', admin_hash, ADMIN_ROLE)
        
        # Default viewer: viewer/viewer123
        viewer_hash = self.hash_password('viewer123')
        self.users['viewer'] = User('viewer', viewer_hash, VIEWER_ROLE)
        
        self.save_users()
        print("Default users created:")
        print("  Admin: username='admin', password='admin123'")
        print("  Viewer: username='viewer', password='viewer123'")
    
    def save_users(self):
        """Save users to JSON file."""
        data = {}
        for username, user in self.users.items():
            data[username] = {
                'password_hash': user.password_hash,
                'role': user.role
            }
        
        try:
            with open(self.users_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving users: {e}")
    
    def hash_password(self, password):
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password, password_hash):
        """Verify a password against its hash."""
        return self.hash_password(password) == password_hash
    
    def authenticate(self, username, password):
        """Authenticate a user."""
        if username in self.users:
            user = self.users[username]
            if self.verify_password(password, user.password_hash):
                return user
        return None
    
    def get_user(self, username):
        """Get a user by username."""
        return self.users.get(username)
    
    def add_user(self, username, password, role):
        """Add a new user (admin only)."""
        if username in self.users:
            return False
        
        password_hash = self.hash_password(password)
        self.users[username] = User(username, password_hash, role)
        self.save_users()
        return True
    
    def update_user(self, username, password=None, role=None):
        """Update a user (admin only)."""
        if username not in self.users:
            return False
        
        user = self.users[username]
        if password:
            user.password_hash = self.hash_password(password)
        if role:
            user.role = role
        
        self.save_users()
        return True
    
    def delete_user(self, username):
        """Delete a user (admin only)."""
        if username not in self.users:
            return False
        
        # Prevent deleting the last admin
        if self.users[username].is_admin():
            admin_count = sum(1 for u in self.users.values() if u.is_admin())
            if admin_count <= 1:
                return False
        
        del self.users[username]
        self.save_users()
        return True
    
    def change_password(self, username, old_password, new_password):
        """Change a user's password."""
        if username not in self.users:
            return False, "User not found"
        
        user = self.users[username]
        
        # Verify old password
        if not self.verify_password(old_password, user.password_hash):
            return False, "Current password is incorrect"
        
        # Update password
        user.password_hash = self.hash_password(new_password)
        self.save_users()
        return True, "Password changed successfully"

# Global auth manager instance
auth_manager = AuthManager()

# Initialize login manager
login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login."""
    return auth_manager.get_user(user_id)

@login_manager.unauthorized_handler
def unauthorized():
    """Handle unauthorized access."""
    return redirect(url_for('login'))

def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('Admin access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def can_edit_required(f):
    """Decorator to require edit permissions (admin only)."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.can_edit():
            return {'error': 'Permission denied. Admin access required.'}, 403
        return f(*args, **kwargs)
    return decorated_function

