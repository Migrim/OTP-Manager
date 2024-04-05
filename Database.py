import os
import sqlite3
import shutil
from datetime import datetime

def init_db():
    try:
        db_path = "otp.db"
        print("Checking for database backup...")
        backup_folder = "backup"
        current_date = datetime.now().strftime("%Y-%m-%d")
        backup_filename = f"otp_{current_date}.db"
        backup_path = os.path.join(backup_folder, backup_filename)

        if not os.path.exists(backup_path):
            if not os.path.exists(backup_folder):
                os.makedirs(backup_folder)
            shutil.copy(db_path, backup_path)
            print(f"Database backup created at {backup_path}")
        else:
            print("Backup already exists for today.")

        if not os.path.exists(db_path):
            print("Creating otp.db database...")
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()

                print("Creating otp_secrets table...")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS otp_secrets (
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        email TEXT DEFAULT 'none',
                        secret TEXT NOT NULL,
                        otp_type TEXT NOT NULL,
                        refresh_time INTEGER NOT NULL,
                        company_id INTEGER,
                        FOREIGN KEY (company_id) REFERENCES companies (id)
                    )
                """)

                print("Creating users table...")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        last_login_time TEXT,
                        session_token TEXT,
                        is_admin INTEGER DEFAULT 0,
                        enable_pagination INTEGER DEFAULT 0,
                        show_timer INTEGER DEFAULT 0,
                        show_otp_type INTEGER DEFAULT 1,
                        show_content_titles INTEGER DEFAULT 1,
                        alert_color TEXT DEFAULT 'alert-primary',
                        text_color TEXT DEFAULT '#FFFFFF',
                        show_emails INTEGER DEFAULT 0,
                        show_company INTEGER DEFAULT 0
                    )
                """)

                print("Creating companies table...")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS companies (
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        kundennummer TEXT
                    )
                """)

                print("Creating statistics table...")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS statistics (
                        id INTEGER PRIMARY KEY,
                        logins_today INTEGER NOT NULL,
                        times_refreshed INTEGER NOT NULL,
                        date TEXT NOT NULL
                    )
                """)

                print("Running consistency check...")
                cursor.execute("PRAGMA foreign_key_check")
                consistency_result = cursor.fetchall()
                if not consistency_result:
                    print("Database consistency check passed.")
                else:
                    print("Database consistency check failed. Inconsistent foreign key constraints.")

                db.commit()
                print("Database initialized successfully.")
                
        else:
            print("otp.db database already exists.")
            
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                print("Running consistency check...")
                cursor.execute("PRAGMA foreign_key_check")
                consistency_result = cursor.fetchall()
                if not consistency_result:
                    print("Database consistency check passed.")
                    print("Exiting Database initialization.")
                else:
                    print("Database consistency check failed. Inconsistent foreign key constraints.")

    except sqlite3.Error as e:
        print(f"An error occurred while initializing the database: {e}")

if __name__ == "__main__":
    init_db()
