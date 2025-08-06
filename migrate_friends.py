#!/usr/bin/env python3
"""
Migration script to add Friend table to the database
"""

import sqlite3
import os
from datetime import datetime

def migrate_friends():
    """Add Friend table to the database"""
    db_path = 'instance/user_data.db'
    
    if not os.path.exists(db_path):
        print("Database not found. Please run the app first to create the database.")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if Friend table already exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='friend'")
        if cursor.fetchone():
            print("Friend table already exists.")
            return
        
        # Create Friend table
        cursor.execute('''
            CREATE TABLE friend (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id VARCHAR(10) NOT NULL,
                friend_id VARCHAR(10) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, friend_id)
            )
        ''')
        
        conn.commit()
        print("Friend table created successfully!")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_friends() 