from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets
import hashlib

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.String(10), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length for hashed passwords
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Admin fields
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='user')  # user, moderator, admin, super_admin
    permissions = db.Column(db.Text, nullable=True)  # JSON string of permissions
    notes = db.Column(db.Text, nullable=True)  # Admin notes about the user
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def has_permission(self, permission):
        """Check if user has specific permission"""
        if self.is_admin:
            return True
        if not self.permissions:
            return False
        import json
        try:
            user_permissions = json.loads(self.permissions)
            return permission in user_permissions
        except:
            return False

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.String(10), nullable=False)
    receiver_id = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)  # Soft delete
    
    # Admin fields
    is_flagged = db.Column(db.Boolean, default=False)
    flagged_reason = db.Column(db.String(200), nullable=True)
    flagged_by = db.Column(db.String(10), db.ForeignKey('user.id'), nullable=True)
    flagged_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<Message {self.id}>'

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(10), db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.String(10), db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique friendship pairs
    __table_args__ = (db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)
    
    def __repr__(self):
        return f'<Friend {self.user_id} -> {self.friend_id}>'

class SecurityLog(db.Model):
    """Security audit log"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(10), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # login, logout, message_sent, etc.
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<SecurityLog {self.action} by {self.user_id}>'

class AdminAction(db.Model):
    """Admin action log"""
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.String(10), db.ForeignKey('user.id'), nullable=False)
    target_user_id = db.Column(db.String(10), db.ForeignKey('user.id'), nullable=True)
    action_type = db.Column(db.String(50), nullable=False)  # ban_user, delete_message, etc.
    action_details = db.Column(db.Text, nullable=True)  # JSON string with details
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    
    def __repr__(self):
        return f'<AdminAction {self.action_type} by {self.admin_id}>'

class SystemSettings(db.Model):
    """System-wide settings"""
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=True)
    setting_type = db.Column(db.String(20), default='string')  # string, int, bool, json
    description = db.Column(db.String(200), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.String(10), db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<SystemSettings {self.setting_key}>'