import os
import sqlite3
import shutil
import re
import time
from datetime import datetime
from logging_config import db_logger

def init_db():
    try:
        instance_folder = "instance"
        db_filename = "otp.db"
        db_path = os.path.join(instance_folder, db_filename)
        is_new_database = not os.path.exists(db_path)

        if not os.path.exists(instance_folder):
            os.makedirs(instance_folder)

        db_logger.info(">>> [CHECK] Checking for database backup...")
        backup_folder = "backup"
        current_date = datetime.now().strftime("%Y-%m-%d")
        backup_filename = f"otp_{current_date}.db"
        backup_path = os.path.join(backup_folder, backup_filename)

        if not os.path.exists(backup_path):
            if not os.path.exists(backup_folder):
                os.makedirs(backup_folder)
            if os.path.exists(db_path):
                shutil.copy(db_path, backup_path)
                db_logger.info(f"+++ [SUCCESS] Database backup created at {backup_path}")
            else:
                db_logger.warning("--- [WARNING] No database to back up.")
        else:
            db_logger.info("### [INFO] Backup already exists for today.")

        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()

            db_logger.info(">>> [CHECK] Ensuring database tables are set up...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS companies (
                    company_id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    kundennummer INTEGER UNIQUE,
                    password TEXT
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
            db_logger.info("+++ [SUCCESS] Database tables verified or created successfully.")

            if is_new_database:
                db_logger.info(">>> [ACTION] Inserting default companies 'Public' and 'Private'...")
                cursor.execute("INSERT INTO companies (name) VALUES ('Public'), ('Private')")
                db.commit()
                db_logger.info("+++ [SUCCESS] Default companies added.")

            db_logger.info(">>> [CHECK] Adding default admin user if not exists...")
            cursor.execute("SELECT id FROM users WHERE id = 1")
            if cursor.fetchone() is None:
                cursor.execute("INSERT INTO users (id, username, password, is_admin) VALUES (1, 'admin', '1234', 1)")
                db.commit()
                db_logger.info("+++ [SUCCESS] Default admin user created.")

            db_logger.info(">>> [CHECK] Running database consistency check...")
            cursor.execute("PRAGMA foreign_key_check")
            consistency_result = cursor.fetchall()
            if not consistency_result:
                db_logger.info("+++ [SUCCESS] Database consistency check passed.")
            else:
                db_logger.error("*** [ERROR] Database consistency check failed. Inconsistent foreign key constraints.")

            db_logger.info(">>> [CHECK] Validating OTP secrets format...")
            cursor.execute("SELECT id, secret FROM otp_secrets")
            secrets = cursor.fetchall()
            for id, secret in secrets:
                if not re.match('^[A-Z0-9]+$', secret):
                    cleaned_secret = re.sub('[^A-Z0-9]', '', secret.upper())
                    cursor.execute("UPDATE otp_secrets SET secret = ? WHERE id = ?", (cleaned_secret, id))
                    db_logger.info(f"+++ [SUCCESS] Updated secret for ID {id}: {cleaned_secret}")

            forbidden_words = [
                'INVALID', 'FORBIDDEN', 'ERROR', 'SELECT', 'DROP', 'INSERT', 'DELETE',
                'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'TRIGGER', 'GRANT', 'REVOKE', 'COMMIT',
                'ROLLBACK', 'SAVEPOINT', 'FLUSH', 'SHUTDOWN', 'UNION', 'INTERSECT', 'EXCEPT',
                'SCRIPT', 'SCRIPTING', 'NULL', 'TRUE', 'FALSE', 'LIMIT', 'TABLE',
                'VIEW', 'KEY', 'INDEX', 'DISTINCT', 'JOIN', 'WHERE', 'ORDER BY', 'GROUP BY',
                'HAVING', 'DECLARE', 'CURSOR', 'FETCH', 'LOCK'
            ]
            db_logger.info(">>> [CHECK] Validating names...")
            cursor.execute("SELECT id, name FROM otp_secrets")
            names = cursor.fetchall()
            for id, name in names:
                if name.strip() == "" or any(word in name.upper() for word in forbidden_words):
                    db_logger.warning(f"--- [WARNING] Invalid name detected for ID {id}: {name}. Please rename the saved Secret!")
                    db_logger.warning(f"--- [WARNING] Name for ID {id} has not been automatically updated!")

            db.commit()
            db_logger.info("+++ [SUCCESS] All records validated and updated as necessary.")

    except sqlite3.Error as e:
        db_logger.error(f"*** [ERROR] An error occurred while initializing the database: {e}")

if __name__ == "__main__":
    db_logger.info(">>> [INFO] Starting hourly database checks...")
    while True:
        init_db()
        db_logger.info(">>> [INFO] Database check completed. Next check in 1 hour.")
        time.sleep(3600)  
