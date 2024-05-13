import os
import sqlite3
import shutil
import re
from datetime import datetime

def init_db():
    try:
        instance_folder = "instance"
        db_filename = "otp.db"
        db_path = os.path.join(instance_folder, db_filename)
        is_new_database = not os.path.exists(db_path)

        if not os.path.exists(instance_folder):
            os.makedirs(instance_folder)

        print("Checking for database backup...")
        backup_folder = "backup"
        current_date = datetime.now().strftime("%Y-%m-%d")
        backup_filename = f"otp_{current_date}.db"
        backup_path = os.path.join(backup_folder, backup_filename)

        if not os.path.exists(backup_path):
            if not os.path.exists(backup_folder):
                os.makedirs(backup_folder)
            if os.path.exists(db_path):
                shutil.copy(db_path, backup_path)
                print(f"Database backup created at {backup_path}")
            else:
                print("No database to back up.")
        else:
            print("Backup already exists for today.")

        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()

            print("Ensuring database tables are set up...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS companies (
                    company_id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    kundennummer INTEGER UNIQUE
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS otp_secrets (
                    id INTEGER PRIMARY KEY UNIQUE,
                    name TEXT NOT NULL DEFAULT 'none' UNIQUE,
                    email TEXT DEFAULT 'none',
                    secret TEXT NOT NULL,
                    otp_type TEXT NOT NULL DEFAULT 'totp',
                    refresh_time INTEGER NOT NULL,
                    company_id INTEGER,
                    FOREIGN KEY (company_id) REFERENCES companies (company_id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY,
                    logins_today INTEGER NOT NULL,
                    times_refreshed INTEGER NOT NULL,
                    date TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    last_login_time INTEGER,
                    session_token TEXT,
                    is_admin INTEGER DEFAULT 0,
                    enable_pagination INTEGER DEFAULT 0,
                    show_timer INTEGER DEFAULT 0,
                    show_otp_type INTEGER DEFAULT 1,
                    show_content_titles INTEGER DEFAULT 1,
                    alert_color TEXT DEFAULT '#333333',
                    text_color TEXT DEFAULT '#FFFFFF',
                    show_emails INTEGER DEFAULT 0,
                    show_company INTEGER DEFAULT 0,
                    font TEXT DEFAULT 'Roboto' 
                )
            """)
            db.commit()
            print("Database tables verified or created successfully.")

            if is_new_database:
                print("Inserting default companies 'Public' and 'Private'...")
                cursor.execute("INSERT INTO companies (name) VALUES ('Public'), ('Private')")
                db.commit()
                print("Default companies added.")

            print("Adding default admin user if not exists...")
            cursor.execute("SELECT id FROM users WHERE id = 1")
            if cursor.fetchone() is None:
                cursor.execute("INSERT INTO users (id, username, password, is_admin) VALUES (1, 'admin', '1234', 1)")
                db.commit()
                print("Default admin user created.")

            print("Running database consistency check...")
            cursor.execute("PRAGMA foreign_key_check")
            consistency_result = cursor.fetchall()
            if not consistency_result:
                print("Database consistency check passed.")
            else:
                print("Database consistency check failed. Inconsistent foreign key constraints.")

            print("Validating OTP secrets format...")
            cursor.execute("SELECT id, secret FROM otp_secrets")
            secrets = cursor.fetchall()
            for id, secret in secrets:
                if not re.match('^[A-Z0-9]+$', secret):
                    cleaned_secret = re.sub('[^A-Z0-9]', '', secret.upper())
                    cursor.execute("UPDATE otp_secrets SET secret = ? WHERE id = ?", (cleaned_secret, id))
                    print(f"Updated secret for ID {id}: {cleaned_secret}")

            forbidden_words = [
                'INVALID', 'FORBIDDEN', 'ERROR', 'SELECT', 'DROP', 'INSERT', 'DELETE',
                'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'TRIGGER', 'GRANT', 'REVOKE', 'COMMIT',
                'ROLLBACK', 'SAVEPOINT', 'FLUSH', 'SHUTDOWN', 'UNION', 'INTERSECT', 'EXCEPT',
                'SCRIPT', 'SCRIPTING', 'NULL', 'TRUE', 'FALSE', 'LIMIT', 'TABLE',
                'VIEW', 'KEY', 'INDEX', 'DISTINCT', 'JOIN', 'WHERE', 'ORDER BY', 'GROUP BY',
                'HAVING', 'DECLARE', 'CURSOR', 'FETCH', 'LOCK'
            ]
            print("Validating names...")
            cursor.execute("SELECT id, name FROM otp_secrets")
            names = cursor.fetchall()
            for id, name in names:
                if name.strip() == "" or any(word in name.upper() for word in forbidden_words):
                    print(f"Invalid name detected for ID {id}: {name}, please rename the saved Secret!")
                    print(f"Name for ID {id} has not been automatically updated!")

            db.commit()
            print("All records validated and updated as necessary.")

    except sqlite3.Error as e:
        print(f"An error occurred while initializing the database: {e}")

if __name__ == "__main__":
    init_db()
