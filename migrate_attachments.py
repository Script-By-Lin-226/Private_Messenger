#!/usr/bin/env python3
"""
Database migration script to add attachment fields to Message table.
"""

import os
import sqlite3
import psycopg2
from psycopg2 import sql

def migrate_postgres():
    """Add attachment fields to PostgreSQL Message table"""
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("No DATABASE_URL set. Skipping PostgreSQL migration.")
        return
    
    print("Connecting to PostgreSQL...")
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    
    try:
        # Add attachment fields to message table
        print("Adding attachment fields to message table...")
        
        # Check if columns already exist before adding them
        cur.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'message' AND column_name IN 
            ('has_attachment', 'attachment_filename', 'attachment_original_name', 'attachment_type', 'attachment_size');
        """)
        existing_columns = [row[0] for row in cur.fetchall()]
        
        # Add columns that don't exist
        if 'has_attachment' not in existing_columns:
            cur.execute("ALTER TABLE message ADD COLUMN has_attachment BOOLEAN DEFAULT FALSE;")
            
        if 'attachment_filename' not in existing_columns:
            cur.execute("ALTER TABLE message ADD COLUMN attachment_filename VARCHAR(255);")
            
        if 'attachment_original_name' not in existing_columns:
            cur.execute("ALTER TABLE message ADD COLUMN attachment_original_name VARCHAR(255);")
            
        if 'attachment_type' not in existing_columns:
            cur.execute("ALTER TABLE message ADD COLUMN attachment_type VARCHAR(50);")
            
        if 'attachment_size' not in existing_columns:
            cur.execute("ALTER TABLE message ADD COLUMN attachment_size INTEGER;")
        
        # Make content nullable for file-only messages
        cur.execute("ALTER TABLE message ALTER COLUMN content DROP NOT NULL;")
        
        conn.commit()
        print("✅ Successfully added attachment fields to message table.")
        
    except Exception as e:
        print(f"Error adding attachment fields: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

def migrate_sqlite():
    """Add attachment fields to SQLite Message table"""
    # SQLite migration would go here if needed
    print("SQLite attachment migration not implemented yet.")

def main():
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith('postgres'):
        migrate_postgres()
    else:
        migrate_sqlite()

if __name__ == "__main__":
    main()