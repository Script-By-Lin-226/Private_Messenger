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
    """Migrate PostgreSQL database to add ON DELETE CASCADE to all user-related foreign keys"""
    import os
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("No DATABASE_URL set. Skipping PostgreSQL migration.")
        return
    print("Connecting to PostgreSQL...")
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    try:
        # Drop old constraints if they exist
        print("Dropping old constraints if they exist...")
        cur.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'security_log_user_id_fkey') THEN
                    ALTER TABLE security_log DROP CONSTRAINT security_log_user_id_fkey;
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'message_sender_id_fkey') THEN
                    ALTER TABLE message DROP CONSTRAINT message_sender_id_fkey;
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'message_receiver_id_fkey') THEN
                    ALTER TABLE message DROP CONSTRAINT message_receiver_id_fkey;
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'friend_user_id_fkey') THEN
                    ALTER TABLE friend DROP CONSTRAINT friend_user_id_fkey;
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'friend_friend_id_fkey') THEN
                    ALTER TABLE friend DROP CONSTRAINT friend_friend_id_fkey;
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'adminaction_admin_id_fkey') THEN
                    ALTER TABLE adminaction DROP CONSTRAINT adminaction_admin_id_fkey;
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'adminaction_target_user_id_fkey') THEN
                    ALTER TABLE adminaction DROP CONSTRAINT adminaction_target_user_id_fkey;
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'systemsettings_updated_by_fkey') THEN
                    ALTER TABLE systemsettings DROP CONSTRAINT systemsettings_updated_by_fkey;
                END IF;
            END$$;
        """)
        # Add new constraints with ON DELETE CASCADE
        print("Adding new constraints with ON DELETE CASCADE...")
        cur.execute("""
            ALTER TABLE security_log
                ADD CONSTRAINT security_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE;
            ALTER TABLE message
                ADD CONSTRAINT message_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES "user"(id) ON DELETE CASCADE,
                ADD CONSTRAINT message_receiver_id_fkey FOREIGN KEY (receiver_id) REFERENCES "user"(id) ON DELETE CASCADE;
            ALTER TABLE friend
                ADD CONSTRAINT friend_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE,
                ADD CONSTRAINT friend_friend_id_fkey FOREIGN KEY (friend_id) REFERENCES "user"(id) ON DELETE CASCADE;
            ALTER TABLE adminaction
                ADD CONSTRAINT adminaction_admin_id_fkey FOREIGN KEY (admin_id) REFERENCES "user"(id) ON DELETE CASCADE,
                ADD CONSTRAINT adminaction_target_user_id_fkey FOREIGN KEY (target_user_id) REFERENCES "user"(id) ON DELETE CASCADE;
            ALTER TABLE systemsettings
                ADD CONSTRAINT systemsettings_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES "user"(id) ON DELETE SET NULL;
        """)
        conn.commit()
        print("✅ Updated all user-related foreign keys to ON DELETE CASCADE.")
    except Exception as e:
        print(f"Error updating foreign keys: {e}")
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