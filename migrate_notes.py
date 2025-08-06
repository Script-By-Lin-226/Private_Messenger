#!/usr/bin/env python3
"""
Migration script to add notes field to User model
"""

import os
import sys
from app import app, db
from sqlalchemy import text

def migrate_notes_field():
    """Add notes field to User table if it doesn't exist"""
    print("🔧 Migrating User table to add notes field...")
    
    with app.app_context():
        try:
            # Check if notes column exists
            result = db.session.execute(text("""
                SELECT COUNT(*) FROM pragma_table_info('user') 
                WHERE name = 'notes'
            """))
            
            column_exists = result.scalar() > 0
            
            if column_exists:
                print("✅ Notes column already exists in User table")
                return True
            
            # Add notes column
            print("📝 Adding notes column to User table...")
            db.session.execute(text("""
                ALTER TABLE user 
                ADD COLUMN notes TEXT
            """))
            
            db.session.commit()
            print("✅ Successfully added notes column to User table")
            return True
            
        except Exception as e:
            print(f"❌ Error adding notes column: {e}")
            db.session.rollback()
            return False

def main():
    """Run the migration"""
    print("🚀 Starting User notes field migration...")
    print("=" * 50)
    
    success = migrate_notes_field()
    
    print("=" * 50)
    if success:
        print("🎉 Migration completed successfully!")
    else:
        print("⚠️ Migration failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 