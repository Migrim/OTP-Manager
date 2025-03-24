from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, RadioField, HiddenField
from wtforms.validators import DataRequired, Length 
from pyotp import totp, hotp
from flask_session import Session
from wtforms import IntegerField
from wtforms.validators import InputRequired, NumberRange
from wtforms.validators import Email, Optional
from wtforms import StringField, SelectField, PasswordField
from wtforms.validators import DataRequired
from flask import jsonify
from flask_bcrypt import Bcrypt
from search import search_otp
from generation import is_base32, generate_otp_code
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from flask_login import LoginManager, current_user, login_user
from search import search_blueprint
from flask_login import UserMixin
from math import ceil
from flask import send_file
from collections import defaultdict
from subprocess import Popen, PIPE
from markupsafe import Markup
from flask_cors import CORS
from time import ctime
from threading import Lock
import pyotp
import ntplib
import time
import requests
import requests
import bcrypt
import shutil
import os
import subprocess 
import sqlite3
import logging
import re
import uuid
import signal
import json
import psutil
import configparser
import schedule
import sys
import signal
from threading import Thread

from forms.otp_forms import OTPForm
from forms.user_forms import UserForm
from forms.company_form import CompanyForm
from forms.user import User

from logging_config import my_logger

config = configparser.ConfigParser()
config.read('config.ini')

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app)
start_time = datetime.now()
app.config['SECRET_KEY'] = config.get('server', 'secret_key', fallback='your-secret-key')
base_dir = os.path.dirname(os.path.abspath(__file__))
app.config['DATABASE'] = os.path.join(base_dir, config.get('database', 'path', fallback='instance/otp.db'))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)
Session(app)
Bootstrap(app)

from admin_routes import admin_bp
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(search_blueprint, url_prefix='/search_blueprint')

login_manager = LoginManager()
login_manager.init_app(app)

app.logger.handlers = []
app.logger.propagate = False
app.logger.addHandler(my_logger.handlers[0]) 

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.disabled = True

broadcast_message = None
slow_requests_counter = 0
flash_messages = []

def find_database_py():
    current_dir = os.getcwd() 
    print("Searching for Database.py in:", current_dir)
    while True:
        database_path = os.path.join(current_dir, "Database.py")
        print("Checking:", database_path)
        if os.path.isfile(database_path):  
            return database_path  
        current_dir = os.path.dirname(current_dir)
        if current_dir == os.path.dirname(current_dir):
            break  
    return None

database_path = find_database_py()
if database_path:
    subprocess.Popen(["python3", database_path])
else:
    print("Database.py not found.")

@app.login_manager.user_loader
def load_user(user_id):
    db_path = app.config['DATABASE']
    with sqlite3.connect(db_path, timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()

    if user_row:
        return User(
            user_id=user_row[0], 
            username=user_row[1], 
            is_admin=bool(user_row[5]),
            enable_pagination=bool(user_row[6]),
            show_timer=bool(user_row[7]),
            show_otp_type=bool(user_row[8]),
            show_content_titles=bool(user_row[9]),
            show_emails=bool(user_row[12]),  
            show_company=bool(user_row[13]),
            font=(user_row[14])
        )
    return None

def save_to_db(otp_secrets):
    db_path = app.config['DATABASE']
    conn = sqlite3.connect(db_path, timeout=30.0)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM otp_secrets")

    last_row_id = None
    for otp_secret in otp_secrets:
        email = otp_secret.get('email', "none")
        cursor.execute("""
        INSERT INTO otp_secrets (name, email, secret, otp_type, refresh_time, company_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (otp_secret['name'], email, otp_secret['secret'], otp_secret['otp_type'], otp_secret['refresh_time'], otp_secret['company_id']))
        last_row_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return last_row_id

def save_companies_to_db(companies):
    db_path = app.config['DATABASE']
    conn = sqlite3.connect(db_path, timeout=30.0)
    cursor = conn.cursor()

    for company in companies:
        cursor.execute("SELECT password FROM companies WHERE company_id = ?", (company['company_id'],))
        result = cursor.fetchone()
        existing_password = result[0] if result else None
        
        if not existing_password:
            flash(f"No existing password found for company {company['name']}. Please check the database.", 'error')
            continue

        cursor.execute("""
        INSERT OR IGNORE INTO companies (company_id, name, kundennummer, password)
        VALUES (?, ?, ?, ?)
        """, (company['company_id'], company['name'], company['kundennummer'], existing_password))

        cursor.execute("""
        UPDATE companies SET name = ?, kundennummer = ? WHERE company_id = ?
        """, (company['name'], company['kundennummer'], company['company_id']))

    conn.commit()
    conn.close()

def load_from_db(secret_id=None):
    db_path = app.config['DATABASE']
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        if secret_id:
            cursor.execute("""
                SELECT 
                    otp_secrets.name, 
                    otp_secrets.email, 
                    otp_secrets.secret, 
                    otp_secrets.otp_type, 
                    otp_secrets.refresh_time, 
                    otp_secrets.company_id, 
                    companies.name AS company_name
                FROM otp_secrets
                LEFT JOIN companies ON otp_secrets.company_id = companies.company_id
                WHERE otp_secrets.name = ?
            """, (secret_id,))
            row = cursor.fetchone()
            return {
                'name': row[0], 
                'email': row[1],  
                'secret': row[2], 
                'otp_type': row[3], 
                'refresh_time': row[4], 
                'company_id': row[5], 
                'company': row[6] if row[6] else 'Unbekannt'
            } if row else None
        else:
            cursor.execute("""
                SELECT 
                    otp_secrets.name, 
                    otp_secrets.email, 
                    otp_secrets.secret, 
                    otp_secrets.otp_type, 
                    otp_secrets.refresh_time, 
                    otp_secrets.company_id, 
                    companies.name AS company_name
                FROM otp_secrets
                LEFT JOIN companies ON otp_secrets.company_id = companies.company_id
            """)
            secrets = [
                {
                    'name': row[0], 
                    'email': row[1],  
                    'secret': row[2],  
                    'otp_type': row[3], 
                    'refresh_time': row[4], 
                    'company_id': row[5], 
                    'company': row[6] if row[6] else 'Unbekannt'
                } 
                for row in cursor.fetchall()
            ]

            # **Sorting by company first, then prioritizing "admin" secrets**
            sorted_secrets = sorted(secrets, key=lambda x: (x['company'], not "admin" in x['name'].lower(), x['name'].lower()))

            return sorted_secrets

def load_companies_from_db():
    db_path = app.config['DATABASE']  
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name, kundennummer FROM companies ORDER BY company_id")
        return [{'company_id': row[0], 'name': row[1], 'kundennummer': row[2]} for row in cursor.fetchall()]

def get_current_user():
    user_id = session.get('user_id') 
    if not user_id:
        return None  

    db_path = app.config['DATABASE']  
    with sqlite3.connect(db_path, timeout=30.0) as db:
        db.row_factory = sqlite3.Row 
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()

    if user_row:
        show_emails = user_row["show_emails"] == 1
        show_company = user_row["show_company"] == 1
        return User(user_id=user_row["id"], username=user_row["username"], 
                    is_admin=bool(user_row["is_admin"]), enable_pagination=bool(user_row["enable_pagination"]), 
                    show_timer=bool(user_row["show_timer"]), show_otp_type=bool(user_row["show_otp_type"]), 
                    show_content_titles=bool(user_row["show_content_titles"]), show_emails=show_emails, show_company=show_company)
    else:
        return None

def get_all_users():
    db_path = app.config['DATABASE']  
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, username FROM users")
        users = cursor.fetchall()
    return users

@app.route('/show_endpoints')
def show_endpoints():
    import pprint
    return pprint.pformat(app.url_map)

@app.route('/get_flash_messages')
def get_flash_messages():
    messages = session.get('_flashes', [])
    session.pop('_flashes', None)  
    categorized_messages = [{'category': category, 'message': message} for category, message in messages]
    return jsonify(categorized_messages)

def update_statistics(logins=0, refreshed=0):
    today = datetime.now().strftime('%Y-%m-%d')
    db_path = app.config['DATABASE']  
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM statistics WHERE date = ?", (today,))
        stats = cursor.fetchone()
        
        if stats:
            cursor.execute("UPDATE statistics SET logins_today = logins_today + ?, times_refreshed = times_refreshed + ? WHERE date = ?", (logins, refreshed, today))
        else:
            cursor.execute("INSERT INTO statistics (logins_today, times_refreshed, date) VALUES (?, ?, ?)", (logins, refreshed, today))
        
        db.commit()

def get_statistics():
    today = datetime.now().strftime('%Y-%m-%d')
    db_path = app.config['DATABASE']  
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM statistics WHERE date = ?", (today,))
        stats = cursor.fetchone()
        if stats:
            return {'logins_today': stats[1], 'times_refreshed': stats[2]}
        else:
            return {'logins_today': 0, 'times_refreshed': 0}

def get_older_statistics(limit=15):
    db_path = app.config['DATABASE']  
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM statistics ORDER BY date DESC LIMIT ?", (limit,))
        return cursor.fetchall()

def find_db_path(db_name='otp.db'):
    exclude_dirs = ['/tmp', '/var/tmp', os.path.expanduser('~/.local/share/Trash'), os.path.expanduser('~/.Trash')]
    appdata_dir = os.getenv('APPDATA') if os.name == 'nt' else os.path.expanduser('~/.config')
    exclude_dirs.append(appdata_dir)

    for root, dirs, files in os.walk('/'):
        if any(root.startswith(ex_dir) for ex_dir in exclude_dirs):
            continue
        if db_name in files:
            return os.path.join(root, db_name)
    raise FileNotFoundError(f"Database file '{db_name}' not found.")

@app.route('/get_db_path', methods=['GET'])
def get_db_path():
    try:
        db_path = find_db_path()
        return jsonify({'db_path': db_path}), 200
    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 404

@app.route('/get_older_statistics')
def older_statistics():
    stats = get_older_statistics(15)  
    result = [{
        'logins_today': stat[1],
        'times_refreshed': stat[2],
        'day_index': index  
    } for index, stat in enumerate(stats)]
    return jsonify(result)

@app.route('/logout')
def logout():
    user_id = session.pop('user_id', None)
    session_token = session.pop('session_token', None)
    username = current_user.username if user_id else 'Unknown' 

    app.logger.info(f"User '{username}' is attempting to log out.")

    if user_id is None:
        app.logger.warning("No user ID found in session during logout attempt.")
    else:
        app.logger.info(f"User '{username}' with session token {session_token} is logging out.")

    try:
        db_path = app.config['DATABASE']  
        with sqlite3.connect(db_path, timeout=30.0) as db:
            cursor = db.cursor()
            cursor.execute("UPDATE users SET session_token = NULL WHERE id = ?", (user_id,))
            db.commit()
            app.logger.info(f"User ID {user_id} successfully logged out, session token cleared in database.")
    except sqlite3.Error as e:
        app.logger.error(f"Error logging out User ID {user_id}: {e}")

    flash("You have been logged out successfully.", "success")

    app.logger.info(f"User '{username}' successfully logged out, redirecting to login.")
    return redirect(url_for('login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        session_token = session.get('session_token')

        if not user_id or not session_token:
            return redirect(url_for('login'))
        
        db_path = app.config['DATABASE']  
        with sqlite3.connect(db_path, timeout=30.0) as db:
            cursor = db.cursor()
            cursor.execute("SELECT session_token FROM users WHERE id = ?", (user_id,))
            db_session_token = cursor.fetchone()

            if not db_session_token or session_token != db_session_token[0]:
                session.pop('user_id', None)
                session.pop('session_token', None)
                return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = session.get('user_id')

    if request.method == 'POST':
        data = request.get_json()

        show_timer = 1 if data.get('show_timer') == 'on' else 0
        show_otp_type = 1 if data.get('show_otp_type') == 'on' else 0
        show_content_titles = 1 if data.get('show_content_titles') == 'on' else 0
        alert_color = data.get('alert_color')
        show_emails = 1 if data.get('show_emails') == 'on' else 0
        show_company = 1 if data.get('show_company') == 'on' else 0

        color_map = {
            # Lighter Pastel Colors
            '#FFB3BA': '#B22222',  # Pastel Red with Dark Red Text
            '#FFDFBA': '#A0522D',  # Pastel Orange with Sienna Text
            '#FFFFBA': '#8B8000',  # Pastel Yellow with Olive Text
            '#BAFFC9': '#006400',  # Pastel Green with Dark Green Text
            '#BAE1FF': '#00008B',  # Pastel Blue with Dark Blue Text
            '#D9BAFF': '#4B0082',  # Pastel Purple with Indigo Text
            '#FFB3FF': '#8B008B',  # Pastel Pink with Dark Magenta Text
            '#CFCFCF': '#696969',  # Light Gray with Dim Gray Text
            '#B3FFFF': '#008B8B',  # Pastel Cyan with Dark Cyan Text
            '#FFE4E1': '#CD5C5C',  # Light Coral with Indian Red Text
            '#E6E6FA': '#4B0082',  # Lavender with Indigo Text
            '#FFFACD': '#8B8000',  # Lemon Chiffon with Olive Text
            '#FAFAD2': '#556B2F',  # Light Goldenrod with Dark Olive Green Text
            
            # Darker Pastel Colors
            '#8E8D8A': '#333333',  # Warm Gray with Dark Gray Text
            '#A59C94': '#333333',  # Pastel Brown with Dark Gray Text
            '#7F8283': '#333333',  # Pastel Gray with Dark Gray Text
            '#7A9E9F': '#2F4F4F',  # Pastel Teal with Dark Slate Gray Text
            '#8DA399': '#2E8B57',  # Pastel Olive with Sea Green Text
            '#B39DDB': '#4B0082',  # Soft Violet with Indigo Text
            '#B0A8B9': '#4B0082',  # Pastel Purple-Gray with Indigo Text
            '#CCB7AE': '#8B4513',  # Pastel Peach with Saddle Brown Text
            '#B2AD8E': '#6B4226',  # Muted Olive with Dark Brown Text
            '#8D8468': '#333333',  # Dark Pastel Tan with Dark Gray Text

            # Default Dark Color
            '#333333': '#FFFFFF',  # Dark Gray with White Text
        }

        def get_brightness(hex_color):
            hex_color = hex_color.lstrip('#')
            rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            return 0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2]

        brightness = get_brightness(alert_color)
        text_color = color_map.get(alert_color, '#FFFFFF' if brightness < 120 else '#000000')

        try:
            db_path = app.config['DATABASE']
            with sqlite3.connect(db_path, timeout=30.0) as db:
                cursor = db.cursor()
                print("Database connection established.")
                cursor.execute(
                    "UPDATE users SET show_timer = ?, show_otp_type = ?, show_content_titles = ?, alert_color = ?, text_color = ?, show_emails = ?, show_company = ? WHERE id = ?",
                    (show_timer, show_otp_type, show_content_titles, alert_color, text_color, show_emails, show_company, user_id)
                )
                db.commit()
                print("Database updated successfully.")
                flash('Settings updated successfully', 'success')
        except sqlite3.Error as e:
            print("Error updating database:", str(e))
            flash('An error occurred while updating settings.', 'danger')

    db_path = app.config['DATABASE']
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT show_timer, show_otp_type, show_content_titles, alert_color, text_color, show_emails, show_company FROM users WHERE id = ?",
            (user_id,)
        )
        settings = cursor.fetchone()
        if settings:
            current_user.show_timer, current_user.show_otp_type, current_user.show_content_titles, current_user.alert_color, current_user.text_color, current_user.show_emails, current_user.show_company = settings
            flash('Personal settings loaded', 'info')

    return render_template('settings.html', show_timer=current_user.show_timer, show_otp_type=current_user.show_otp_type, alert_color=current_user.alert_color, show_emails=current_user.show_emails, show_company=current_user.show_company)

@app.route('/refresh_codes_v2')
@login_required
def refresh_codes_v2():
    username = current_user.username  

    update_statistics(refreshed=1)
    otp_secrets = load_from_db()
    otp_codes = []

    for otp in otp_secrets:
        current_otp_code, next_otp_code = generate_current_and_next_otp(otp)
        if current_otp_code is None:
            flash('Invalid OTP-Secret!', 'error')
            app.logger.warning(f"User '{username}' encountered invalid OTP secret '{otp['name']}' during refresh.")
            continue
        otp_codes.append({
            'name': otp['name'],
            'current_otp': current_otp_code,
            'next_otp': next_otp_code
        })

    return jsonify({"otp_codes": otp_codes})

@app.route('/refresh_specific_code')
@login_required
def refresh_specific_code():
    name = request.args.get('name')
    otp_secret = next((item for item in load_from_db() if item['name'] == name), None)
    
    if not otp_secret:
        return jsonify({'error': 'Secret not found'}), 404
    
    current_otp_code, _ = generate_current_and_next_otp(otp_secret)
    return jsonify({'otp_code': {
        'name': otp_secret['name'],
        'current_otp': current_otp_code
    }})

def generate_current_and_next_otp(otp):
    try:
        if otp['otp_type'] == 'totp':
            totp_maker = pyotp.TOTP(otp['secret'])
            current_otp = totp_maker.now()
            next_otp = totp_maker.at(datetime.now() + timedelta(seconds=otp['refresh_time']))
        else:
            return None, None
        return current_otp, next_otp
    except Exception as e:
        print(f"Error generating OTP: {e}")
        return None, None

@app.route('/reset/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if not new_password:
            flash('Password is missing!')
            print(f"Password reset attempted without providing a new password for user_id: {user_id}")
            logging.warning(f'Password reset attempted without providing a new password for user_id: {user_id}')
            return render_template('reset_password.html', user_id=user_id)
        
        hashed_password = generate_password_hash(new_password, method='sha256')
        
        try:
            db_path = app.config['DATABASE']  
            with sqlite3.connect(db_path, timeout=30.0) as db:
                cursor = db.cursor()
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
                db.commit()
            flash('Password changed successfully!')
            print(f"Password for user_id {user_id} was successfully updated.")
            logging.info(f'Password for user_id {user_id} was successfully updated.')
        except sqlite3.Error as e:
            flash('There was a problem changing the password!')
            print(f"Error updating password for user_id {user_id}: {e}")
            logging.error(f'Error updating password for user_id {user_id}: {e}')
        
        return redirect(url_for('home'))
    
    logging.info(f'Password reset page accessed for user_id: {user_id}')
    print(f"Password reset page accessed for user_id: {user_id}")
    return render_template('reset_password.html', user_id=user_id)

def get_last_login_time_from_db():
    user_id = session.get('user_id')
    if user_id:
        db_path = app.config['DATABASE']  
        with sqlite3.connect(db_path, timeout=30.0) as db:
            cursor = db.cursor()
            cursor.execute("SELECT last_login_time FROM users WHERE id = ?", (user_id,))
            last_login_time = cursor.fetchone()
            if last_login_time:
                return last_login_time[0]
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    flash("Please log in to gain access", "warning")

    if 'user_id' in session:
        flash("You are already logged in.", "info")
        app.logger.info(f"User with ID {session['user_id']} attempted to access login while already logged in.")
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        keep_logged_in = 'keep_logged_in' in request.form

        app.logger.info(f"Login attempt for username: {username}")

        try:
            db_path = app.config['DATABASE']
            with sqlite3.connect(db_path, timeout=30.0) as db:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user_record = cursor.fetchone()

            if user_record:
                stored_password = user_record[2]
                user_id = user_record[0]
                is_admin = bool(user_record[5])

                if is_cleartext(stored_password):
                    hashed_password = bcrypt.generate_password_hash(stored_password).decode('utf-8')
                    with sqlite3.connect(db_path, timeout=30.0) as db:
                        cursor = db.cursor()
                        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
                        db.commit()
                    stored_password = hashed_password
                    flash("Password for your account has been securely updated.", "info")

                if bcrypt.check_password_hash(stored_password, password):
                    user_obj = User(user_id, username, is_admin=is_admin)
                    login_user(user_obj, remember=keep_logged_in)

                    session.permanent = keep_logged_in
                    session_token = str(uuid.uuid4())
                    session['user_id'] = user_id
                    session['session_token'] = session_token

                    with sqlite3.connect(db_path, timeout=30.0) as db:
                        cursor = db.cursor()
                        cursor.execute("UPDATE statistics SET logins_today = logins_today + 1")
                        cursor.execute("UPDATE users SET session_token = ? WHERE id = ?", (session_token, user_id))
                        db.commit()

                    app.logger.info(f"Successful login for user ID: {user_id} (username: {username})")

                    flash("Access granted!", "success")
                    if is_admin and password == "1234":
                        flash("You are using the default password. Please consider changing it!", "warning")

                    return redirect(url_for('home'))
                else:
                    app.logger.warning(f"Failed login attempt for username: {username} - Invalid credentials")
                    flash('Invalid credentials! Please try again.', 'danger')
                    return redirect(url_for('login'))
            else:
                app.logger.warning(f"Failed login attempt for username: {username} - User not found")
                flash('User not found! Please check your username.', 'danger')
                return redirect(url_for('login'))

        except Exception as e:
            app.logger.error(f"Error during login attempt for username: {username} - {str(e)}")
            flash('An error occurred during login. Please try again later.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

def is_cleartext(password):
    if not password.startswith(('$2b$', '$2a$', '$2y$')):
        return True

    if len(password) != 60:
        return True

    return False

def perform_login_actions(user, keep_logged_in):
    session_token = str(uuid.uuid4())
    session['user_id'] = user[0]
    session['session_token'] = session_token
    session.permanent = keep_logged_in

    my_logger.info(f"User: {user[1]} Logged in!")

    last_login_time = datetime.now()
    db_path = app.config['DATABASE'] 
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute("UPDATE users SET last_login_time = ? WHERE id = ?", (last_login_time, user[0]))
        db.commit()

    user_obj = UserMixin()
    user_obj.id = user[0]
    user_obj.username = user[1]
    login_user(user_obj)

    return redirect(url_for('home'))

@app.template_filter('category_icon')
def category_icon_filter(category):
    icons = {
        'info': 'info',
        'success': 'check_circle',
        'warning': 'warning',
        'error': 'error',
        'auth': 'fingerprint'
    }
    return icons.get(category, 'info')  

app.jinja_env.filters['category_icon'] = category_icon_filter

@app.route('/about')
@login_required
def about():
    stats = get_statistics()
    stored_otps = len(load_from_db())
    logins_today = stats['logins_today']
    times_refreshed = stats['times_refreshed']
    uptime = get_uptime()
    current_server_time = datetime.now()
    last_user_login_time = "logic missing!"
    current_server_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

    ram = psutil.virtual_memory()
    ram_usage = ram.percent  
    ram_total_gb = ram.total / (1024**3)  
    ram_used_gb = ram.used / (1024**3)  

    cpu_usage = psutil.cpu_percent(interval=None)  
    disk = psutil.disk_usage('/')
    disk_usage = disk.percent

    older_stats = get_older_statistics()
    uptime = get_uptime()
    is_admin = current_user.is_admin

    return render_template(
        'about.html',
        stored_otps=stored_otps,
        ram_usage=f"{ram_usage}% / {ram_used_gb:.2f} GB",
        cpu_usage=cpu_usage, 
        disk_usage=disk_usage,
        logins_today=logins_today,
        times_refreshed=times_refreshed,
        uptime=uptime,
        last_user_login_time=last_user_login_time,
        current_server_time=current_server_time,
        older_stats=older_stats,
        is_admin=is_admin
    )

def get_uptime():
    current_time = datetime.now()
    uptime = current_time - start_time

    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    return f"{days} Days {hours}h:{minutes}m:{seconds}s"

@app.route('/get_stats', methods=['GET'])
def get_stats_json():
    stats = get_statistics()
    stored_otps = len(load_from_db())
    logins_today = stats['logins_today']
    times_refreshed = stats['times_refreshed']
    uptime = get_uptime()
    
    server_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

    ram = psutil.virtual_memory()
    ram_usage = ram.percent
    ram_total_gb = ram.total / (1024**3)
    ram_used_gb = ram.used / (1024**3)

    cpu_usage = psutil.cpu_percent(interval=None)
    disk_usage = psutil.disk_usage('/').percent

    last_login_time = get_last_login_time_from_db()

    return jsonify({
        'stored_otps': stored_otps,
        'ram_usage': f"{ram_usage}% / {ram_used_gb:.2f} GB",
        'cpu_usage': cpu_usage, 
        'disk_usage': disk_usage,
        'logins_today': logins_today,
        'times_refreshed': times_refreshed,
        'uptime': uptime,
        'current_server_time': server_time,
        'last_user_login_time': last_login_time 
    })

@app.route('/get_otp_v2/<name>', methods=['GET'])
@login_required
def get_otp_v2(name):
    otp_secrets = load_from_db()
    username = current_user.username 

    for otp_secret in otp_secrets:
        if otp_secret.get('name', 'Unnamed') == name:
            current_otp, next_otp = generate_current_and_next_otp(otp_secret)
            if current_otp is None or next_otp is None:
                app.logger.warning(f"User '{username}' encountered invalid OTP secret for '{name}'.")
                return 'Invalid OTP secret', 400
            app.logger.info(f"User '{username}' accessed OTP secret '{name}'.")
            return render_template('otp.html', otp=otp_secret, current_otp=current_otp, next_otp=next_otp)
    
    app.logger.warning(f"User '{username}' requested non-existent OTP secret '{name}'.")
    return 'Secret Not Found', 404

def get_user_colors(user_id):
    db_path = app.config['DATABASE']  
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute("SELECT alert_color, text_color FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        if result:
            return result[0], result[1] 
        else:
            return 'alert-primary', '#FFFFFF'  

def get_user_alert_color(user_id):
    db_path = app.config['DATABASE']  
    with sqlite3.connect(db_path, timeout=30.0) as db:
        cursor = db.cursor()
        cursor.execute("SELECT alert_color FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        return result[0] if result else 'alert-primary'  

def nav():
    user_id = session.get('user_id')
    print(f"Current user ID: {user_id}")

    if user_id is not None:
        text_color = get_user_text_color(user_id)
        print(f"User alert color: {text_color}")
        return render_template('navbar.html', text_color=text_color)
    else:
        print("No current user")
        return render_template('navbar.html', text_color='default-color')

@app.context_processor
def inject_user_text_color():
    user_id = session.get('user_id')
    if user_id:
        text_color = get_user_text_color(user_id)
    else:
        text_color = 'default-color'
    return {'text_color': text_color}

def get_user_text_color(user_id):
    db_path = app.config['DATABASE']  
    try:
        with sqlite3.connect(db_path, timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT text_color FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
            if result:
                return result[0]  
            else:
                return "#FFFFFF"  
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "#FFFFFF"

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    form = OTPForm()
    otp_secrets = session.get('filtered_secrets', load_from_db())
    otp_codes = []
    current_user = get_current_user()

    items_per_page = 0 if not current_user.enable_pagination else 9

    page = request.args.get('page', type=int, default=1)

    try:
        if form.validate_on_submit():
            app.logger.info(f'User {current_user.username} submitted OTP form.')
            new_secret = {
                'name': form.name.data,
                'company': form.company.data if form.company.data else 'N/A',
                'secret': form.secret.data,
                'otp_type': form.otp_type.data,
                'refresh_time': form.refresh_time.data
            }
            otp_secrets.append(new_secret)
            save_to_db(otp_secrets)
            app.logger.info(f'User {current_user.username} added new OTP secret "{new_secret["name"]}".')
            flash(f'New OTP secret "{new_secret["name"]}" added successfully!', 'success')
            return redirect(url_for('home'))
        
        companies = sorted(load_companies_from_db(), key=lambda x: x['name'])
        selected_company = request.args.get('company')

        if selected_company:
            app.logger.info(f'User {current_user.username} is filtering OTP secrets by company: {selected_company}.')
            otp_secrets = [otp for otp in otp_secrets if otp['company'] == selected_company]
            if not otp_secrets:
                flash(f'No secrets found for company: {selected_company}', 'info')
            else:
                flash(f'Secrets filtered by company: {selected_company}', 'info')

        for otp in otp_secrets:
            current_otp, next_otp = generate_current_and_next_otp(otp)
            if current_otp is None or next_otp is None:
                app.logger.warning(f'User {current_user.username} encountered invalid OTP secret "{otp["name"]}".')
                flash('Invalid OTP secret')
                continue
            otp['current_otp'] = current_otp
            otp['next_otp'] = next_otp
            otp_codes.append(otp)

        grouped_otp_codes = defaultdict(list)
        for otp_code in otp_codes:
            grouped_otp_codes[otp_code['company']].append(otp_code)

        unknown_group = grouped_otp_codes.pop('N/A', None) or grouped_otp_codes.pop('Unknown', None)
        grouped_otp_codes = dict(sorted(grouped_otp_codes.items(), key=lambda x: x[0]))
        if unknown_group:
            grouped_otp_codes = {'N/A': unknown_group, **grouped_otp_codes}

        total_otp_count = len(otp_secrets)

        if not otp_codes and selected_company:
            flash(f"No matching secrets for company: {selected_company}", 'info')

        total_pages = ceil(len(otp_codes) / items_per_page) if current_user.enable_pagination else 1
        
        start_index = (page - 1) * items_per_page
        end_index = start_index + items_per_page if items_per_page > 0 else len(otp_codes)

        displayed_otp_codes = otp_codes[start_index:end_index]
        alert_color, text_color = get_user_colors(current_user.id)

        search_name = request.args.get('name')

        if search_name:
            app.logger.info(f'User {current_user.username} is filtering OTP secrets by name: {search_name}.')
            found = False
            for k, v in list(grouped_otp_codes.items()): 
                matched_secrets = [x for x in v if search_name.lower() in x['name'].lower()]
                grouped_otp_codes[k] = matched_secrets
                if matched_secrets:
                    found = True

            if not found:
                flash(f'No secrets found matching name: {search_name}', 'info')
            else:
                flash(f'Secrets filtered by name: {search_name}', 'info')

        show_emails = current_user.show_emails
        show_company = current_user.show_company
        return render_template('home.html', form=form, grouped_otp_codes=grouped_otp_codes, total_otp_count=total_otp_count, companies=companies, search_name=search_name, page=page, total_pages=total_pages, enable_pagination=current_user.enable_pagination,  alert_color=alert_color, text_color=text_color, username=current_user.username, show_emails=show_emails, show_company=show_company)

    except Exception as e:
        app.logger.error(f'User {current_user.username} encountered an error on the home page: {e}', exc_info=True)
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return render_template('home.html', alert_color=alert_color)

@app.route('/copy_otp', methods=['POST'])
@login_required  
def copy_otp():
    username = current_user.username  

    try:
        data = request.get_json()
        app.logger.debug(f"Received data for /copy_otp: {data}")

        if not data or 'otpName' not in data:
            flash("Invalid request. Please try again.", "error")
            app.logger.warning(f"User '{username}' made an invalid request to /copy_otp.")
            return redirect(url_for('home'))

        otp_name = data['otpName']
        otp_secrets = load_from_db()  
        otp_code = None

        for otp in otp_secrets:
            if otp['name'] == otp_name:
                otp_code, _ = generate_current_and_next_otp(otp)
                app.logger.info(f"User '{username}' generated OTP for '{otp_name}'.")
                break

        if otp_code:
            with open('otp_code.json', 'w') as json_file:
                json.dump({'otpName': otp_name, 'otpCode': otp_code}, json_file)
            flash(f"OTP for '{otp_name}' copied to the clipboard.", "info")
            app.logger.info(f"OTP for '{otp_name}' copied to the clipboard by user '{username}'.")
            return jsonify(success=True)
        else:
            flash(f"No OTP found for {otp_name}.", "error")
            app.logger.warning(f"User '{username}' attempted to copy OTP for '{otp_name}', but no matching OTP was found.")
            return jsonify(success=False, message=f'No OTP found for "{otp_name}".')

    except Exception as e:
        flash("An unexpected error occurred. Please try again.", "error")
        app.logger.error(f"An error occurred for user '{username}' in /copy_otp: {e}")
        return jsonify(success=False, message="An unexpected error occurred.")

@app.route('/get_otp', methods=['GET'])
@login_required 
def get_otp():
    try:
        with open('otp_code.json', 'r') as json_file:
            otp_data = json.load(json_file)
        
        log_event = {
            'username': current_user.username,
            'otp': otp_data,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open('otp_log.json', 'a') as log_file:
            log_file.write(json.dumps(log_event) + '\n')
        
        with open('otp_code.json', 'w') as json_file:
            json.dump({}, json_file)
        
        with open('otp_log.json', 'w') as log_file:
            log_file.write('')  
        
        return jsonify(otp_data)
    except FileNotFoundError:
        flash("OTP not found. Please generate an OTP first.", "error")
        return jsonify({'message': 'OTP not found'}), 404

@app.route('/clear_otp', methods=['POST'])
@login_required
def clear_otp():
    try:
        with open('otp_code.json', 'w') as json_file:
            json.dump({}, json_file)
        return jsonify(success=True)
    except Exception as e:
        print(f"An error occurred in /clear_otp: {e}")
        return jsonify(success=False, message="An unexpected error occurred.")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/edit/<name>', methods=['GET', 'POST'])
@login_required
def edit(name):
    otp_secrets = load_from_db()
    form = OTPForm()
    form.company.choices = [(company['company_id'], company['name']) for company in load_companies_from_db()]

    username = current_user.username  
    secret_found = False

    for i, otp in enumerate(otp_secrets):
        if otp['name'] == name:
            secret_found = True
            if request.method == 'POST':
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    data = request.json
                    original_otp = otp_secrets[i].copy()
                    otp_secrets[i]['name'] = data['name']
                    otp_secrets[i]['secret'] = data['secret']
                    otp_secrets[i]['company_id'] = data['company']
                    otp_secrets[i]['email'] = data.get('email', "none")
                    save_to_db(otp_secrets)
                    
                    app.logger.info(f"User '{username}' updated OTP '{name}' via AJAX.")
                    app.logger.debug(f"Original: {original_otp}")
                    app.logger.debug(f"Updated: {otp_secrets[i]}")
                    
                    flash('OTP updated successfully.', 'success')
                    return jsonify({
                        'message': 'OTP updated successfully via AJAX.',
                        'updated_data': {
                            'name': data['name'],
                            'secret': data['secret'],
                            'company': data['company'],
                        }
                    })
                else:
                    original_otp = otp_secrets[i].copy()
                    otp_secrets[i]['name'] = form.name.data
                    otp_secrets[i]['secret'] = form.secret.data
                    otp_secrets[i]['company_id'] = form.company.data
                    otp_secrets[i]['email'] = form.email.data
                    save_to_db(otp_secrets)
                    
                    app.logger.info(f"User '{username}' updated OTP '{name}' via form.")
                    app.logger.debug(f"Original: {original_otp}")
                    app.logger.debug(f"Updated: {otp_secrets[i]}")
                    
                    flash('OTP updated successfully through form submission.', 'success')
                    return redirect(url_for('home'))

    if not secret_found:
        app.logger.warning(f"User '{username}' tried to edit OTP '{name}' but it was not found.")
        flash('Secret Not Found. Unable to edit.', 'error')
    
    return redirect(url_for('home'))

@app.route('/get_start_time')
def get_start_time():
    return jsonify({'start_time': start_time.isoformat()})

@app.route('/broadcast', methods=['POST'])
@login_required
def set_broadcast_message():
    global broadcast_message
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    message = request.form.get('message')
    if message:
        broadcast_message = message
        return jsonify({'status': 'success', 'message': 'Message broadcasted'}), 200
    return jsonify({'status': 'error', 'message': 'No message provided'}), 400

@app.before_request
def check_for_broadcast_message():
    global broadcast_message
    if broadcast_message and request.endpoint != 'broadcast':
        flash(broadcast_message)

@app.route('/delete_secret/<name>', methods=['POST'])
@login_required
def delete_secret(name):
    db_path = app.config['DATABASE']
    username = current_user.username 
    
    try:
        with sqlite3.connect(db_path, timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM otp_secrets WHERE name = ?", (name,))
            conn.commit()
        flash(f'Successfully deleted secret with name: {name}', 'success')
        app.logger.info(f"User '{username}' successfully deleted OTP secret with name '{name}'.")
    except sqlite3.Error as e:
        flash(f'Could not delete secret: {e}', 'danger')
        app.logger.error(f"Error occurred while user '{username}' tried to delete OTP secret with name '{name}': {e}")
    
    return redirect(url_for('home'))

@app.route('/delete/<name>', methods=['POST'])
@login_required
def delete(name):
    username = current_user.username  
    
    otp_secrets = load_from_db()
    otp_secrets = [otp for otp in otp_secrets if 'name' in otp and otp['name'] != name]
    save_to_db(otp_secrets)
    flash(f'Successfully deleted secret with name: {name}', 'success')
    app.logger.info(f"User '{username}' successfully deleted OTP secret with name '{name}' from local storage.")
    
    return redirect(url_for('home'))

@app.route('/delete_user/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):
    username = current_user.username 
    
    if current_user.get_id() != "admin":
        flash("Only the root can delete users.", 'error')
        app.logger.warning(f"User '{username}' attempted to delete user with ID {user_id} but lacks admin privileges.")
        return redirect(url_for('admin.admin_settings'))

    try:
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path, timeout=30.0) as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
        flash("User successfully deleted.")
        app.logger.info(f"Admin '{username}' successfully deleted user with ID {user_id}.")
    except sqlite3.Error as e:
        flash("Failed to delete user.")
        app.logger.error(f"Error occurred while admin '{username}' tried to delete user with ID {user_id}: {e}")
    
    return redirect(url_for('admin.admin_settings'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = OTPForm()
    companies_from_db = load_companies_from_db()
    form.company.choices = [(company['company_id'], company['name']) for company in companies_from_db]

    if form.validate_on_submit():
        action = request.form.get('action')
        name = form.name.data.strip()
        email = form.email.data.strip() or "none"
        secret = form.secret.data.strip().upper()
        otp_type = form.otp_type.data.lower().strip()
        refresh_time = form.refresh_time.data
        company_id = form.company.data
        username = current_user.username 

        if otp_type not in ['totp', 'hotp']:
            flash('Invalid OTP type. Choose either TOTP or HOTP.', 'error')
            app.logger.warning(f"User '{username}' attempted to add OTP with invalid type '{otp_type}'.")
            return render_template('add.html', form=form)
        
        if len(secret) < 16 or len(secret) > 32:
            flash('Secret length should be between 16 and 32 characters.', 'error')
            app.logger.warning(f"User '{username}' attempted to add OTP with invalid secret length '{len(secret)}'.")
            return render_template('add.html', form=form)

        if not secret.isalnum():
            flash('Secret must contain only alphanumeric characters.', 'error')
            app.logger.warning(f"User '{username}' attempted to add OTP with non-alphanumeric secret '{secret}'.")
            return render_template('add.html', form=form)

        if not isinstance(refresh_time, int) or refresh_time <= 0:
            flash('Refresh time must be a positive number.', 'error')
            app.logger.warning(f"User '{username}' attempted to add OTP with invalid refresh time '{refresh_time}'.")
            return render_template('add.html', form=form)

        valid_base32 = re.fullmatch('[A-Z2-7=]{16,32}', secret, re.IGNORECASE)
        if not valid_base32 or len(secret) % 8 != 0:
            flash('Secret must be a valid Base32 string with a length that is a multiple of 8 characters.', 'error')
            app.logger.warning(f"User '{username}' attempted to add OTP with invalid Base32 secret '{secret}'.")
            return render_template('add.html', form=form)

        selected_company_name = next((company['name'] for company in companies_from_db if company['company_id'] == company_id), 'N/A')

        existing_otp_secrets = load_from_db()
        if any(existing_secret['name'] == name for existing_secret in existing_otp_secrets):
            flash(f"A secret with the name '{name}' already exists!", 'error')
            app.logger.warning(f"User '{username}' attempted to add duplicate OTP secret with name '{name}'.")
            form.name.data = ""
            return render_template('add.html', form=form)

        new_otp_secret = {
            'name': name,
            'email': email,
            'secret': secret,
            'otp_type': otp_type,
            'refresh_time': refresh_time,
            'company_id': company_id,
            'company': selected_company_name
        }

        existing_otp_secrets.append(new_otp_secret)
        save_to_db(existing_otp_secrets)

        app.logger.info(f"User '{username}' added new OTP secret '{name}' for company '{selected_company_name}'.")

        if action == 'add':
            flash(f"New OTP secret '{name}' added successfully.", 'info')
            return redirect(url_for('home'))
        elif action == 'add_view':
            flash(f"New OTP secret '{name}' added successfully. Viewing details.", 'info')
            return redirect(url_for('view_otp', secret_id=new_otp_secret['name']))

    return render_template('add.html', form=form)

@app.route('/view_otp/<string:secret_id>') 
@login_required
def view_otp(secret_id):
    otp_secret = load_from_db(secret_id) 
    if not otp_secret:
        flash("No OTP secret found with the given ID.", "error")
        return redirect(url_for('home'))

    otp_code_info = generate_otp_code(otp_secret)  
    return render_template('view_otp.html', secret=otp_code_info)

@app.route('/copy_otp_flash')
def copy_otp_flash():
    flash('OTP Copied to Clipboard!', 'info')
    return jsonify(success=True)

def run_schedule():
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('config.ini')
    port = config.getint('server', 'port')

    print(f"""
 ██████╗ ████████╗██████╗                                     
██╔═══██╗╚══██╔══╝██╔══██╗                                    
██║   ██║   ██║   ██████╔╝                                    
██║   ██║   ██║   ██╔═══╝                                     
╚██████╔╝   ██║   ██║                                         
 ╚═════╝    ╚═╝   ╚═╝                                         
                                                              
███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗ 
████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗
██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝
██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
                                                                                   
    ----------- Running on port {port} -----------
    """)

    logging.basicConfig(level=logging.INFO)
    logging.info(f"Server starting on port {port}...")

    scheduler_thread = Thread(target=run_schedule)
    scheduler_thread.daemon = True
    scheduler_thread.start()

    try:
        app.run(debug=True, port=port, host='0.0.0.0', use_reloader=False)
    except KeyboardInterrupt:
        logging.info("Server stopped by user.")
