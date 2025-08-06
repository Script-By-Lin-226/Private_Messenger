#!/usr/bin/env python3
"""
Database migration script to add admin functionality
This script will add the new admin columns to existing database tables
"""

import os
import sys
from app import app, db
from sqlalchemy import text

def migrate_database():
    """Migrate database to add admin functionality"""
    print("🔄 Database Migration - Adding Admin Functionality")
    print("=" * 60)
    
    try:
        with app.app_context():
            # Check if admin columns already exist
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('user')]
            
            print("Current user table columns:", columns)
            
            # Add missing columns to user table
            migrations = []
            
            if 'is_admin' not in columns:
                migrations.append("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT FALSE")
            
            if 'is_active' not in columns:
                migrations.append("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT TRUE")
            
            if 'is_verified' not in columns:
                migrations.append("ALTER TABLE user ADD COLUMN is_verified BOOLEAN DEFAULT FALSE")
            
            if 'role' not in columns:
                migrations.append("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'user'")
            
            if 'permissions' not in columns:
                migrations.append("ALTER TABLE user ADD COLUMN permissions TEXT")
            
            if 'created_at' not in columns:
                migrations.append("ALTER TABLE user ADD COLUMN created_at DATETIME")
            
            if 'login_attempts' not in columns:
                migrations.append("ALTER TABLE user ADD COLUMN login_attempts INTEGER DEFAULT 0")
            
            if 'locked_until' not in columns:
                migrations.append("ALTER TABLE user ADD COLUMN locked_until DATETIME")
            
            # Add missing columns to message table
            message_columns = [col['name'] for col in inspector.get_columns('message')]
            
            if 'is_flagged' not in message_columns:
                migrations.append("ALTER TABLE message ADD COLUMN is_flagged BOOLEAN DEFAULT FALSE")
            
            if 'flagged_reason' not in message_columns:
                migrations.append("ALTER TABLE message ADD COLUMN flagged_reason VARCHAR(200)")
            
            if 'flagged_by' not in message_columns:
                migrations.append("ALTER TABLE message ADD COLUMN flagged_by VARCHAR(10)")
            
            if 'flagged_at' not in message_columns:
                migrations.append("ALTER TABLE message ADD COLUMN flagged_at DATETIME")
            
            # Execute migrations
            if migrations:
                print(f"Found {len(migrations)} migrations to apply:")
                for migration in migrations:
                    print(f"  - {migration}")
                
                print("\nApplying migrations...")
                for migration in migrations:
                    try:
                        db.session.execute(text(migration))
                        print(f"✅ Applied: {migration}")
                    except Exception as e:
                        print(f"⚠️  Warning (may already exist): {migration}")
                        print(f"   Error: {e}")
                
                db.session.commit()
                print("✅ All migrations completed")
            else:
                print("✅ Database is already up to date")
            
            # Create new tables if they don't exist
            print("\n📋 Creating new admin tables...")
            
            # Check if AdminAction table exists
            if not inspector.has_table('admin_action'):
                print("Creating AdminAction table...")
                from db_model import AdminAction
                AdminAction.__table__.create(db.engine)
                print("✅ AdminAction table created")
            else:
                print("✅ AdminAction table already exists")
            
            # Check if SystemSettings table exists
            if not inspector.has_table('system_settings'):
                print("Creating SystemSettings table...")
                from db_model import SystemSettings
                SystemSettings.__table__.create(db.engine)
                print("✅ SystemSettings table created")
            else:
                print("✅ SystemSettings table already exists")
            
            print("\n🎉 Database migration completed successfully!")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

def verify_migration():
    """Verify that migration was successful"""
    print("\n🔍 Verifying migration...")
    
    try:
        with app.app_context():
            inspector = db.inspect(db.engine)
            
            # Check user table columns
            user_columns = [col['name'] for col in inspector.get_columns('user')]
            required_user_columns = ['is_admin', 'is_active', 'is_verified', 'role', 'permissions', 'created_at', 'login_attempts', 'locked_until']
            
            missing_user_columns = [col for col in required_user_columns if col not in user_columns]
            if missing_user_columns:
                print(f"❌ Missing user columns: {missing_user_columns}")
                return False
            else:
                print("✅ All user columns present")
            
            # Check message table columns
            message_columns = [col['name'] for col in inspector.get_columns('message')]
            required_message_columns = ['is_flagged', 'flagged_reason', 'flagged_by', 'flagged_at']
            
            missing_message_columns = [col for col in required_message_columns if col not in message_columns]
            if missing_message_columns:
                print(f"❌ Missing message columns: {missing_message_columns}")
                return False
            else:
                print("✅ All message columns present")
            
            # Check admin tables
            if inspector.has_table('admin_action'):
                print("✅ AdminAction table exists")
            else:
                print("❌ AdminAction table missing")
                return False
            
            if inspector.has_table('system_settings'):
                print("✅ SystemSettings table exists")
            else:
                print("❌ SystemSettings table missing")
                return False
            
            print("✅ Migration verification successful!")
            return True
            
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False

def main():
    """Main migration function"""
    print("🚀 Private Messenger Database Migration")
    print("=" * 60)
    
    # Run migration
    if migrate_database():
        # Verify migration
        if verify_migration():
            print("\n🎉 Migration completed successfully!")
            print("\n📝 Next Steps:")
            print("1. Run: python3 create_admin.py")
            print("2. Create your admin user")
            print("3. Access admin dashboard at /admin")
        else:
            print("\n❌ Migration verification failed!")
    else:
        print("\n❌ Migration failed!")

if __name__ == "__main__":
    main() 