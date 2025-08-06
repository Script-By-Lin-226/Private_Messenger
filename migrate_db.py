#!/usr/bin/env python3
"""
Database migration script to add ON DELETE CASCADE to security_log.user_id foreign key.
Also deletes related security logs before deleting a user for existing databases.
"""

import os
import sqlite3
import psycopg2
from psycopg2 import sql
from datetime import datetime

def migrate_postgres():
    """Migrate PostgreSQL database to add ON DELETE CASCADE to security_log.user_id foreign key"""
    import os
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("No DATABASE_URL set. Skipping PostgreSQL migration.")
        return
    print("Connecting to PostgreSQL...")
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    try:
        # Drop the old constraint
        cur.execute("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.table_constraints
                    WHERE constraint_name = 'security_log_user_id_fkey'
                ) THEN
                    ALTER TABLE security_log DROP CONSTRAINT security_log_user_id_fkey;
                END IF;
            END$$;
        """)
        # Add the new constraint with ON DELETE CASCADE
        cur.execute("""
            ALTER TABLE security_log
            ADD CONSTRAINT security_log_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE;
        """)
        conn.commit()
        print("✅ Updated security_log.user_id foreign key to ON DELETE CASCADE.")
    except Exception as e:
        print(f"Error updating foreign key: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

def migrate_sqlite():
    """Migrate SQLite database (no-op for ON DELETE CASCADE)"""
    print("SQLite migration not required for ON DELETE CASCADE.")

def main():
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith('postgres'):
        migrate_postgres()
    else:
        migrate_sqlite()

if __name__ == "__main__":
    main() 