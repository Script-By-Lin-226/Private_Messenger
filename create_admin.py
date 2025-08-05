#!/usr/bin/env python3
"""
Script to create the first admin user and initialize the admin system
Run this script to set up admin functionality
"""

import os
import sys
from app import app, db, User, SystemSettings, hash_password, generate_id
from datetime import datetime

def create_admin_user():
    """Create the first admin user"""
    print("🔧 Setting up Admin System")
    print("=" * 50)
    
    # Check if admin already exists
    existing_admin = User.query.filter_by(is_admin=True).first()
    if existing_admin:
        print(f"✅ Admin user already exists: {existing_admin.username}")
        return existing_admin
    
    print("No admin user found. Let's create one!")
    
    # Get admin details
    username = input("Enter admin username: ").strip()
    if not username:
        print("❌ Username cannot be empty")
        return None
    
    # Check if username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print("❌ Username already exists")
        return None
    
    password = input("Enter admin password: ").strip()
    if len(password) < 8:
        print("❌ Password must be at least 8 characters long")
        return None
    
    confirm_password = input("Confirm admin password: ").strip()
    if password != confirm_password:
        print("❌ Passwords do not match")
        return None
    
    # Create admin user
    try:
        admin_user = User(
            id=generate_id(),
            username=username,
            password=hash_password(password),
            is_admin=True,
            is_active=True,
            is_verified=True,
            role='super_admin'
        )
        
        db.session.add(admin_user)
        db.session.commit()
        
        print(f"✅ Admin user created successfully: {username}")
        print(f"   User ID: {admin_user.id}")
        print(f"   Role: {admin_user.role}")
        return admin_user
        
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        db.session.rollback()
        return None

def initialize_system_settings():
    """Initialize default system settings"""
    print("\n📋 Initializing System Settings")
    print("-" * 30)
    
    default_settings = [
        {
            'key': 'max_login_attempts',
            'value': '5',
            'type': 'int',
            'description': 'Maximum failed login attempts before account lockout'
        },
        {
            'key': 'lockout_duration_minutes',
            'value': '15',
            'type': 'int',
            'description': 'Account lockout duration in minutes'
        },
        {
            'key': 'message_length_limit',
            'value': '1000',
            'type': 'int',
            'description': 'Maximum message length in characters'
        },
        {
            'key': 'rate_limit_requests',
            'value': '20',
            'type': 'int',
            'description': 'Number of requests allowed per rate limit window'
        },
        {
            'key': 'rate_limit_window_minutes',
            'value': '60',
            'type': 'int',
            'description': 'Rate limit window in minutes'
        },
        {
            'key': 'maintenance_mode',
            'value': 'false',
            'type': 'bool',
            'description': 'Enable maintenance mode'
        },
        {
            'key': 'registration_enabled',
            'value': 'true',
            'type': 'bool',
            'description': 'Allow new user registrations'
        }
    ]
    
    created_count = 0
    for setting in default_settings:
        existing = SystemSettings.query.filter_by(setting_key=setting['key']).first()
        if not existing:
            new_setting = SystemSettings(
                setting_key=setting['key'],
                setting_value=setting['value'],
                setting_type=setting['type'],
                description=setting['description']
            )
            db.session.add(new_setting)
            created_count += 1
            print(f"✅ Created setting: {setting['key']}")
    
    if created_count > 0:
        db.session.commit()
        print(f"✅ Created {created_count} system settings")
    else:
        print("✅ All system settings already exist")

def show_admin_info(admin_user):
    """Show admin user information"""
    print("\n👤 Admin User Information")
    print("-" * 30)
    print(f"Username: {admin_user.username}")
    print(f"User ID: {admin_user.id}")
    print(f"Role: {admin_user.role}")
    print(f"Admin: {admin_user.is_admin}")
    print(f"Active: {admin_user.is_active}")
    print(f"Verified: {admin_user.is_verified}")
    print(f"Created: {admin_user.created_at}")

def main():
    """Main function"""
    print("🚀 Private Messenger Admin Setup")
    print("=" * 50)
    
    try:
        with app.app_context():
            # Ensure database tables exist
            db.create_all()
            print("✅ Database tables created/verified")
            
            # Create admin user
            admin_user = create_admin_user()
            if not admin_user:
                print("❌ Failed to create admin user")
                return
            
            # Initialize system settings
            initialize_system_settings()
            
            # Show admin info
            show_admin_info(admin_user)
            
            print("\n🎉 Admin system setup complete!")
            print("\n📝 Next Steps:")
            print("1. Log in with your admin credentials")
            print("2. Access the admin dashboard at /admin")
            print("3. Manage users, messages, and system settings")
            print("\n🔗 Admin Dashboard: http://localhost:5000/admin")
            
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 