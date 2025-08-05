#!/usr/bin/env python3
"""
Database migration script to add online status fields to existing databases.
Run this script to update existing databases with the new online status tracking fields.
"""

import sqlite3
import os
from datetime import datetime

def migrate_database():
    """Migrate the database to add online status fields"""
    db_path = 'instance/user_data.db'
    
    if not os.path.exists(db_path):
        print("Database file not found. Creating new database...")
        return
    
    print("Starting database migration...")
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if the new columns already exist
        cursor.execute("PRAGMA table_info(user)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add last_seen column if it doesn't exist
        if 'last_seen' not in columns:
            print("Adding last_seen column...")
            cursor.execute("ALTER TABLE user ADD COLUMN last_seen DATETIME")
        
        # Add is_online column if it doesn't exist
        if 'is_online' not in columns:
            print("Adding is_online column...")
            cursor.execute("ALTER TABLE user ADD COLUMN is_online BOOLEAN")
        
        # Update existing users with current timestamp
        print("Updating existing users with current timestamp...")
        current_time = datetime.utcnow().isoformat()
        cursor.execute("UPDATE user SET last_seen = ?, is_online = 0 WHERE last_seen IS NULL", (current_time,))
        
        # Commit changes
        conn.commit()
        print("Database migration completed successfully!")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database() 