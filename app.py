from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, RadioField
from wtforms.validators import DataRequired, Length 
from pyotp import totp, hotp
from flask_session import Session
from wtforms import IntegerField
from wtforms.validators import InputRequired, NumberRange
from wtforms import StringField, SelectField, PasswordField
from wtforms.validators import DataRequired
from flask import jsonify
from search import search_otp
from generation import is_base32, generate_otp_code
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from flask_login import LoginManager, UserMixin, current_user, login_user
from search import search_blueprint
from math import ceil
from flask import send_file
from collections import defaultdict
from markupsafe import Markup
from flask_cors import CORS
import shutil
import os
import subprocess 
import sqlite3
import logging
import re
import uuid
import signal

logging.basicConfig(filename='MV.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
my_logger = logging.getLogger('MV_logger')

app = Flask(__name__)
CORS(app)
start_time = datetime.now()
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
Session(app)
Bootstrap(app)

from admin_routes import admin_bp
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(search_blueprint, url_prefix='/search_blueprint')

login_manager = LoginManager()
login_manager.init_app(app)

app.logger.handlers = []
app.logger.propagate = False

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.disabled = True

handler = logging.FileHandler('MV.log')
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

formatter = logging.Formatter('%(asctime)s %(message)s')
handler.setFormatter(formatter)

is_restarting = False
broadcast_message = None

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            user = UserMixin()
            user.id = user_data[0]
            user.username = user_data[1]
            user.is_admin = bool(user_data[5])
            user.enable_pagination = bool(user_data[6])
            user.show_timer = bool(user_data[7])
            user.show_otp_type = bool(user_data[8]) 
            user.show_content_titles = bool(user_data[9])
            return user
        return None

def init_db():
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()

            print("Creating otp_secrets table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS otp_secrets (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
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
                    text_color TEXT DEFAULT '#FFFFFF'
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

            db.commit()
            print("Database initialized successfully.")

    except sqlite3.Error as e:
        print(f"An error occurred while initializing the database: {e}")

import sqlite3

def save_to_db(otp_secrets):
    conn = sqlite3.connect('otp.db')
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM otp_secrets")

    for otp_secret in otp_secrets:
        cursor.execute("""
        INSERT INTO otp_secrets (name, secret, otp_type, refresh_time, company_id)
        VALUES (?, ?, ?, ?, ?)
        """, (otp_secret['name'], otp_secret['secret'], otp_secret['otp_type'], otp_secret['refresh_time'], otp_secret['company_id']))

    conn.commit()
    conn.close()

def save_companies_to_db(companies):
    conn = sqlite3.connect("otp.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM companies")

    for company in companies:
        cursor.execute("""
        INSERT OR IGNORE INTO companies (company_id, name)
        VALUES (?, ?)
        """, (company['company_id'], company['name']))

    conn.commit()
    conn.close()

def load_from_db():
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT 
                otp_secrets.name, 
                otp_secrets.secret, 
                otp_secrets.otp_type, 
                otp_secrets.refresh_time, 
                otp_secrets.company_id, 
                companies.name AS company_name
            FROM otp_secrets
            LEFT JOIN companies ON otp_secrets.company_id = companies.company_id
        """)
        return [
            {
                'name': row[0], 
                'secret': row[1], 
                'otp_type': row[2], 
                'refresh_time': row[3], 
                'company_id': row[4], 
                'company': row[5] if row[5] else 'Unbekannt'
            } 
            for row in cursor.fetchall()
        ]

def load_companies_from_db():
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name, kundennummer FROM companies ORDER BY company_id")
        return [{'company_id': row[0], 'name': row[1], 'kundennummer': row[2]} for row in cursor.fetchall()]

class OTPForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=25, message="Der Name darf nicht länger als 25 Zeichen sein.")])
    secret = StringField('Secret', validators=[InputRequired()])
    otp_type = SelectField('OTP Type', validators=[InputRequired()], choices=[('totp', 'TOTP'), ('hotp', 'HOTP')])
    refresh_time = IntegerField('Refresh Time', validators=[InputRequired(), NumberRange(min=1, message="Nur Zahlen sind erlaubt.")], default=30)
    company = SelectField('Company', validators=[InputRequired()], choices=[])
    submit = SubmitField('Submit')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "Enter cool username"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Enter a secure password"})
    submit = SubmitField('Add User')

class CompanyForm(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired()], render_kw={"placeholder": "Enter company name"})
    kundennummer = StringField('Kundennummer', validators=[DataRequired()], render_kw={"placeholder": "Enter Kundennummer"})
    submit_company = SubmitField('Add Company')

def get_current_user():
    return current_user

def get_all_users():
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, username FROM users")
        users = cursor.fetchall()
    return users

@app.route('/show_endpoints')
def show_endpoints():
    import pprint
    return pprint.pformat(app.url_map)

@app.route('/status')
def server_status():
    return jsonify({'status': 'ok'}), 200

@app.before_request
def check_server_status():
    global is_restarting
    if is_restarting and request.endpoint != 'restarting':
        return redirect(url_for('restarting'))

@app.route('/restarting')
def restarting():
    return render_template('restarting.html')

def update_statistics(logins=0, refreshed=0):
    today = datetime.now().strftime('%Y-%m-%d')
    with sqlite3.connect("otp.db") as db:
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
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM statistics WHERE date = ?", (today,))
        stats = cursor.fetchone()
        if stats:
            return {'logins_today': stats[1], 'times_refreshed': stats[2]}
        else:
            return {'logins_today': 0, 'times_refreshed': 0}

def get_older_statistics(limit=5):
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM statistics ORDER BY date DESC LIMIT ?", (limit,))
        return cursor.fetchall()

@app.route('/register', methods=['GET', 'POST'])
def register():
    current_user = get_current_user()
    
    users = get_all_users()
    
    if not current_user or current_user[1] != "admin":
        flash("Nur der Admin kann neue Benutzer registrieren!")
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='sha256')

        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()

        flash('Successfully registered!')
        return redirect(url_for('login'))
    return render_template('register.html', passwords=users)

@app.route('/logout')
def logout():
    user_id = session.pop('user_id', None)
    session_token = session.pop('session_token', None)
    print(f"Attempting to log out user ID {user_id}")

    if user_id is None:
        print("No user ID found in session, redirecting to login.")
    else:
        print(f"Logging out user ID {user_id} with session token {session_token}")

    try:
        with sqlite3.connect("otp.db") as db:
            print("Database connection established.")
            cursor = db.cursor()
            cursor.execute("UPDATE users SET session_token = NULL WHERE id = ?", (user_id,))
            db.commit()
            print(f"Database updated for user ID {user_id}, session token cleared.")
        logging.info(f"User ID {user_id} successfully logged out.")
    except sqlite3.Error as e:
        logging.error(f"Error logging out User ID {user_id}: {e}")
        print(f"Exception occurred: {e}")

    if is_restarting:
        print("Application is restarting, redirecting to login.")
        return redirect(url_for('login'))

    print("Redirecting to login page.")
    return redirect(url_for('login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        session_token = session.get('session_token')

        if not user_id or not session_token:
            app.logger.info("Redirecting to login: No user_id or session_token")
            print(f"Redirecting to login: No user_id or session_token: {user_id}")
            return redirect(url_for('login'))
        
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT session_token FROM users WHERE id = ?", (user_id,))
            db_session_token = cursor.fetchone()

        if not db_session_token or session_token != db_session_token[0]:
            session.pop('user_id', None)
            session.pop('session_token', None)
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

@app.route('/cli', methods=['GET', 'POST'])
@login_required
def cli():
    output = ""
    if request.method == 'POST':
        command = request.form['command']

        output = f"Executed command: {command}"  
    return render_template('cli.html', output=output)

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

        if alert_color in {'#292d26', '#3e4637'}:
            text_color = '#c4b550'
        elif alert_color == '#1b2e4b':
            text_color = '#e9bfff'
        else:
            colors_for_dark_text = {'#ffffff', '#9495df'}
            text_color = '#3E3E41' if alert_color in colors_for_dark_text else '#FFFFFF'

        try:
            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE users SET show_timer = ?, show_otp_type = ?, show_content_titles = ?, alert_color = ?, text_color = ? WHERE id = ?",
                    (show_timer, show_otp_type, show_content_titles, alert_color, text_color, user_id)
                )
                db.commit()

            current_user.show_content_titles = show_content_titles
            current_user.show_timer = show_timer
            current_user.show_otp_type = show_otp_type
            current_user.alert_color = alert_color
            current_user.text_color = text_color

            logging.info(f'User ID {user_id} updated settings successfully.')
            print(f"User ID {user_id} updated settings successfully.")
            return jsonify({'success': True, 'message': 'Settings updated successfully'})
        except sqlite3.Error as e:
            logging.error(f'Error updating settings for User ID {user_id}: {e}')
            print(f"Error updating settings for User ID {user_id}: {e}")
            return jsonify({'success': False, 'message': 'An error occurred while updating settings.'}), 500
    
    alert_color = getattr(current_user, 'alert_color', '#333333')  
    text_color = getattr(current_user, 'text_color', '#FFFFFF') 
    return render_template('settings.html', show_timer=current_user.show_timer, show_otp_type=current_user.show_otp_type, alert_color=alert_color)

@app.route('/refresh_codes_v2')
@login_required
def refresh_codes_v2():
    update_statistics(refreshed=1)
    otp_secrets = load_from_db()
    otp_codes = []

    for otp in otp_secrets:
        otp_code = generate_otp_code(otp)
        if otp_code is None:
            flash('Invalid OTP secret')
            print(f"Invalid OTP secret was attempted to be loaded in the OTP-List")
            continue
        otp_codes.append({
            'name': otp['name'],
            'otp_code': otp_code['otp_code']
        })

    return jsonify({"otp_codes": otp_codes})

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
            with sqlite3.connect("otp.db") as db:
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
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT last_login_time FROM users WHERE id = ?", (user_id,))
            last_login_time = cursor.fetchone()
            if last_login_time:
                return last_login_time[0]
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Accessing /login route")
    if 'user_id' in session:
        print("User is already logged in, redirecting to home")
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Attempting login for username: {username}")
        keep_logged_in = 'keep_logged_in' in request.form

        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            session_token = str(uuid.uuid4())
            session['user_id'] = user[0]
            session['session_token'] = session_token

            session.permanent = keep_logged_in

            my_logger.info(f"User: {username} Logged in!")

            last_login_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute("UPDATE users SET last_login_time = ?, session_token = ? WHERE id = ?", (last_login_time, session_token, user[0]))
                db.commit()

            user_obj = UserMixin()
            user_obj.id = user[0]
            user_obj.username = user[1]
            login_user(user_obj)

            return redirect(url_for('home')) 

        else:
            flash('Die Zugangsdaten konnten nicht validiert werden!')
            my_logger.warning(f"Failed login attempt for user: {username}")

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    last_login_time = get_last_login_time_from_db()
    print("Profile function executed.")
    if current_user.is_authenticated:
        print("User is authenticated.")
        logging.info(f"{current_user.username} is authenticated")
        return make_response(render_template('profile.html', username=current_user.username, last_login_time=last_login_time))
    else:
        print("User is not authenticated.")  
        logging.error(f"{current_user} could not be authenticated!")
        return make_response(redirect(url_for('login')))

@app.route('/about')
@login_required
def about():
    stats = get_statistics()
    stored_otps = len(load_from_db())
    logins_today = stats['logins_today']
    times_refreshed = stats['times_refreshed']
    uptime = get_uptime()
    current_server_time = datetime.now()
    last_user_login_time = "Ihre Logik hier"
    current_server_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

    older_stats = get_older_statistics()
    uptime = get_uptime()
    is_admin = current_user.is_admin

    return render_template(
        'about.html',
        stored_otps=stored_otps,
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
    
    last_login_time = get_last_login_time_from_db()

    return jsonify({
        'stored_otps': stored_otps,
        'logins_today': logins_today,
        'times_refreshed': times_refreshed,
        'uptime': uptime,
        'current_server_time': server_time,
        'last_user_login_time': last_login_time 
    })

@app.route('/get_otp_v2/<name>', methods=['GET'])
def get_otp_v2(name):
    otp_secrets = load_from_db()

    for otp_secret in otp_secrets:
        if otp_secret.get('name', 'Unnamed') == name:
            otp_code = generate_otp_code(otp_secret)
            if otp_code is None:
                return 'Invalid OTP secret', 400
            return render_template('otp.html', otp=otp_secret, otp_code=otp_code['otp_code'])
    return 'Secret Not Found', 404

def get_user_colors(user_id):
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT alert_color, text_color FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        if result:
            return result[0], result[1] 
        else:
            return 'alert-primary', '#FFFFFF'  

def get_user_alert_color(user_id):
    """
    Fetch the user's alert color preference from the database.

    :param user_id: The user's ID.
    :return: The alert color as a string.
    """
    with sqlite3.connect("otp.db") as db:
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
    """Fetch the user's text color from the database.

    Args:
        user_id (int): The ID of the user.

    Returns:
        str: The text color of the user. Returns a default color if not found.
    """
    try:
        with sqlite3.connect("otp.db") as conn:
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

    items_per_page = 0 if not current_user.enable_pagination else 9

    page = request.args.get('page', type=int, default=1)

    try:
        if form.validate_on_submit():
            logging.info('OTP form submission validated.')
            new_secret = {
                'name': form.name.data,
                'company': form.company.data if form.company.data else 'N/A',
                'secret': form.secret.data,
                'otp_type': form.otp_type.data,
                'refresh_time': form.refresh_time.data
            }
            otp_secrets.append(new_secret)
            save_to_db(otp_secrets)
            logging.info(f'New OTP secret added for {new_secret["name"]}.')
            return redirect(url_for('home'))
        
        companies = load_companies_from_db()
        selected_company = request.args.get('company')

        if selected_company:
            logging.info(f'Filtering by company: {selected_company}')
            print(f"Filtering by company: {selected_company}")            
            otp_secrets = [otp for otp in otp_secrets if otp['company'] == selected_company]

        for otp in otp_secrets:
            otp_code = generate_otp_code(otp)
            if otp_code is None:
                logging.warning(f'Invalid OTP secret for {otp["name"]}.')
                print(f"Invalid OTP secret: check logs!")   
                flash('Invalid OTP secret')
                continue
            otp_code['company'] = otp.get('company', 'Unknown')
            otp_codes.append(otp_code)

        grouped_otp_codes = defaultdict(list)
        for otp_code in otp_codes:
            grouped_otp_codes[otp_code['company']].append(otp_code)

        total_otp_count = len(otp_secrets)

        if not otp_codes and selected_company:
            flash(f"No matching secrets for company: {selected_company}")

        total_pages = ceil(len(otp_codes) / items_per_page) if current_user.enable_pagination else 1
        
        start_index = (page - 1) * items_per_page
        end_index = start_index + items_per_page if items_per_page > 0 else len(otp_codes)

        displayed_otp_codes = otp_codes[start_index:end_index]
        alert_color, text_color = get_user_colors(current_user.id)

        search_name = request.args.get('name')
        if search_name:
            logging.info(f'Filtering by name: {search_name}')
            print(f"Filtering by company name")            
            for k, v in list(grouped_otp_codes.items()): 
                grouped_otp_codes[k] = [x for x in v if search_name.lower() in x['name'].lower()]

        return render_template('home.html', form=form, grouped_otp_codes=grouped_otp_codes, total_otp_count=total_otp_count, companies=companies, search_name=search_name, page=page, total_pages=total_pages, enable_pagination=current_user.enable_pagination,  alert_color=alert_color, text_color=text_color)

    except Exception as e:
        logging.error('An error occurred on the home page.', exc_info=True)
        flash('An unexpected error occurred.')
        print(f"An unknown error occurred at the home page") 
        return render_template('home.html', alert_color=alert_color)

@app.route('/get_logs', methods=['GET'])
@login_required
def get_logs():
    log_filename = 'MV.log'
    filter_out = request.args.get('filter_out', 'false').lower() == 'true'

    try:
        with open(log_filename, 'r') as f:
            lines = f.readlines()
        if filter_out:
            lines = [line for line in lines if "Server started" not in line]
        output = "".join(lines)
    except IOError:
        output = "Error: Unable to read log file."

    return jsonify({"logs": output})

@app.route('/view_logs')
@login_required
def view_logs():
    with open("mv.log", "r") as f:
        logs = f.read()
    return render_template('logs.html', logs=logs)

@app.route('/search_form', methods=['GET'])
@login_required
def search_form():
    return render_template('search.html')

@app.errorhandler(404)
def page_not_found(e):
#    logging.error(f"{current_user.username} was redirected or opened an invalid rout!.")
    return render_template('404.html'), 404

@app.route('/search', methods=['GET'])
@login_required
def search_otp():
    query = request.args.get('name', '')
    logging.info(f"Search initiated for query: {query}")
    try:
        all_secrets = fetch_all_secrets()
        
        matched_secrets = [secret for secret in all_secrets if query.lower() in secret['name'].lower()]
        
        logging.info(f"Search results for '{query}': {matched_secrets}")
        return render_template('otp.html', otp_secrets=matched_secrets)
    except Exception as e:
        logging.error(f"Search operation failed: {e}", exc_info=True)
        flash('An error occurred during search.')
        return redirect(url_for('home'))

@app.route('/edit/<name>', methods=['GET', 'POST'])
@login_required
def edit(name):
    otp_secrets = load_from_db()
    
    form = OTPForm()
    form.company.choices = [(company['company_id'], company['name']) for company in load_companies_from_db()]
    
    for i, otp in enumerate(otp_secrets):
        if otp['name'] == name:
            
            if request.method == 'POST':
                if form.validate():
                    logging.info(f"Form is valid. Updating OTP with name: {name}")
                    otp_secrets[i]['name'] = form.name.data
                    otp_secrets[i]['secret'] = form.secret.data
                    otp_secrets[i]['otp_type'] = form.otp_type.data
                    otp_secrets[i]['refresh_time'] = form.refresh_time.data
                    otp_secrets[i]['company'] = form.company.data  

                    save_to_db(otp_secrets)
                    logging.info(f"OTP with name {name} successfully updated.")
                    return redirect(url_for('home'))
                else:
                    logging.warning(f"Form validation failed for OTP with name: {name}")
                    logging.error(form.errors)
            else:
                form.name.data = otp['name']
                form.secret.data = otp['secret']
                form.otp_type.data = otp['otp_type']
                form.refresh_time.data = otp['refresh_time']
                form.company.data = otp.get('company', "none")  
                
                return render_template('edit.html', form=form, name=name)
    
    flash('Secret Not Found')
    logging.error(f"OTP with name {name} not found.")
    return redirect(url_for('home'))

@app.route('/create_backup', methods=['GET'])
@login_required
def create_backup():
    try:
        if not current_user.is_admin:
            logging.warning('Non-admin user attempted to create a backup.')
            print(f"Non-admin user attempted to create a backup.") 
            return jsonify({'success': False, 'message': 'Not authorized'})
        
        db_path = "otp.db"  
        if not os.path.isfile(db_path):
            logging.error('Database file not found for backup.')
            print(f"Database file not found for backup.") 
            return jsonify({'success': False, 'message': 'Database file not found'})

        backup_folder = "backups"
        if not os.path.exists(backup_folder):
            os.makedirs(backup_folder)

        timestamp = datetime.now().strftime("%d.%m.%y-%H:%M")
        backup_file_path = os.path.join(backup_folder, f"otpbcp-{timestamp}.db")
        shutil.copy2(db_path, backup_file_path)
        print(f"Backup created at {backup_file_path}") 
        logging.info(f'Backup created at {backup_file_path}')

        return jsonify({'success': True, 'message': backup_file_path}) 
    except Exception as e:
        logging.error(f'Error creating backup: {e}', exc_info=True)
        print(f"Error creating backup: {e}") 
        return jsonify({'success': False, 'message': str(e)})

@app.route('/load_backup', methods=['POST'])
@login_required
def load_backup():
    try:
        print("load_backup function reached")
        if not current_user.is_admin:
            print("Not authorized")
            return {'success': False, 'message': 'Not authorized'}
        
        file = request.files.get('backup')
        if file:
            backup_folder = "backups"
            backup_file_path = os.path.join(backup_folder, file.filename)
            
            file.save(backup_file_path)
            
            with open(backup_file_path, 'rb') as f_in:
                with open("otp.db", 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            print(f"Copying backup file from {backup_file_path}")
            return {'success': True}
        else:
            print("No backup file provided")
            return {'success': False, 'message': 'No backup file provided'}
    except Exception as e:
        return {'success': False, 'message': str(e)}

@app.route('/list_backups', methods=['GET'])
@login_required
def list_backups():
    try:
        if not current_user.is_admin:
            logging.warning('Non-admin user attempted to list backups.')
            return jsonify({'success': False, 'message': 'Not authorized'})
        
        backup_folder = "backups"
        backups = []
        if os.path.exists(backup_folder):
            # Fetch all backup files and sort them by modification time, newest first
            backups = sorted(os.listdir(backup_folder), key=lambda x: os.path.getmtime(os.path.join(backup_folder, x)), reverse=True)
        
        return jsonify({'success': True, 'backups': backups})
    except Exception as e:
        logging.error(f'Error listing backups: {e}')
        return jsonify({'success': False, 'message': str(e)})

@app.route('/shutdown', methods=['POST'])
@login_required
def shutdown_server():
    if not current_user.is_admin: 
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    try:
        global is_restarting
        is_restarting = True

        shutdown_function = request.environ.get('werkzeug.server.shutdown')
        if shutdown_function is None:
            raise RuntimeError('Not running the Werkzeug server')
        
        shutdown_function()  
        
        return jsonify({'status': 'success', 'message': 'Server shutting down...'}), 200
    except Exception as e:
        is_restarting = False
        logging.error(f"Failed to shut down server: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/server_settings', methods=['GET', 'POST'])
@login_required
def server_settings():
    if not current_user.is_admin:
        flash('Access denied: Admins only.')
        return redirect(url_for('home'))

    current_time = datetime.now()
    uptime = current_time - start_time
    formatted_uptime = f"{uptime.days} Days {uptime.seconds // 3600}h:{(uptime.seconds // 60) % 60}m:{uptime.seconds % 60}s"

    if request.method == 'POST':
        new_port = request.form.get('server_port')
        action = request.form.get('server_action')

        if new_port:
            change_server_port(new_port)

        if action == 'restart':
            restart_server()
        elif action == 'stop':
            shutdown_server()

        flash('Server settings updated successfully!')

    server_time = current_time.strftime('%d/%m/%Y %H:%M:%S')
    current_port = request.host.split(':')[1] if ':' in request.host else 80
    return render_template('server_settings.html', current_port=current_port, uptime=formatted_uptime, server_time=server_time)

@app.route('/get_start_time')
def get_start_time():
    return jsonify({'start_time': start_time.isoformat()})

def change_server_port(new_port):
    pass

def get_current_server_port():
    return os.environ.get('SERVER_PORT', 'default_port')

@app.before_request
def check_for_restarting():
    global is_restarting
    if is_restarting and request.endpoint != 'restarting':
        return redirect(url_for('restarting'))

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

def restart_server():
    global is_restarting
    try:
        logging.info("Server restart initiated.")
        is_restarting = True 
        broadcast_message = 'Server is restarting, you will be redirected.'

        with app.app_context():
            flash(broadcast_message)

        is_restarting = True

        shutdown_function = request.environ.get('werkzeug.server.shutdown')
        if shutdown_function is not None:
            shutdown_function()

        subprocess.Popen(["python", "static/script/reboot.py"])

    except Exception as e:
        is_restarting = False  
        logging.error(f"Failed to restart server: {e}")
        is_restarting = False

@app.route('/delete_secret/<name>', methods=['POST'])
@login_required
def delete_secret(name):
    try:
        with sqlite3.connect('otp.db') as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM otp_secrets WHERE name = ?", (name,))
            conn.commit()
        flash(f'Successfully deleted secret with name: {name}', 'success')
        logging.info(f'Secret with name {name} was successfully deleted.')
    except sqlite3.Error as e:
        flash(f'Could not delete secret: {e}', 'danger')
        logging.error(f'Error when trying to delete secret with name {name}: {e}')
    return redirect(url_for('home'))

@app.route('/delete/<name>', methods=['POST'])
@login_required
def delete(name):
    otp_secrets = load_from_db()
    otp_secrets = [otp for otp in otp_secrets if 'name' in otp and otp['name'] != name]
    save_to_db(otp_secrets)
    return redirect(url_for('home'))

@app.route('/delete_user/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):
    if current_user.get_id() != "admin":
        flash("Only the admin can delete users.")
        return redirect(url_for('admin.admin_settings'))

    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
        flash("User successfully deleted.")
    except sqlite3.Error as e:
        flash("Failed to delete user.")
        logging.error(f"Error deleting user: {e}")

    return redirect(url_for('admin.admin_settings'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = OTPForm()
    companies_from_db = load_companies_from_db()
    form.company.choices = [(company['company_id'], company['name']) for company in companies_from_db]

    if form.validate_on_submit():
        name = form.name.data.strip()
        secret = form.secret.data.strip().upper()
        otp_type = form.otp_type.data.lower().strip()
        refresh_time = form.refresh_time.data
        company_id = form.company.data

        if not re.match(r'^[a-zA-Z0-9@. ]+$', name):
            flash('Invalid characters in name. Only alphanumeric characters, "@", ".", and spaces are allowed.')
            return redirect(url_for('add'))

        if otp_type not in ['totp', 'hotp']:
            flash('Invalid OTP type. Choose either TOTP or HOTP.')
            return redirect(url_for('add'))
        
        if len(secret) < 16:
            flash('Secret is too short. It should be at least 16 characters.')
            return redirect(url_for('add'))

        if not secret.isalnum():
            flash('Secret must contain only alphanumeric characters.')
            return redirect(url_for('add'))

        if not isinstance(refresh_time, int) or refresh_time <= 0:
            flash('Refresh time must be a positive number.')
            return redirect(url_for('add'))

        valid_base32 = re.fullmatch('[A-Z2-7=]{16,}', secret, re.IGNORECASE)
        if not valid_base32 or len(secret) % 8 != 0:
            flash('Secret must be a valid base32 string with a length that is a multiple of 8 characters.')
            return redirect(url_for('add'))

        suspicious_pattern = re.compile(r'(--|;|--|;|/\*|\*/|char|nchar|varchar|nvarchar|alter|begin|cast|create|cursor|declare|delete|drop|end|exec|execute|fetch|insert|kill|open|select|sys|sysobjects|syscolumns|table|update)', re.IGNORECASE)
        if suspicious_pattern.search(name) or suspicious_pattern.search(secret):
            flash('Suspicious patterns detected in input fields.')
            return redirect(url_for('add'))

        selected_company_name = next((company['name'] for company in companies_from_db if company['company_id'] == company_id), 'N/A')

        existing_otp_secrets = load_from_db()
        if any(secret['name'] == name for secret in existing_otp_secrets):
            flash('A secret with this name already exists. Please choose a different name.')
            return redirect(url_for('add'))

        new_otp_secret = {
            'name': name,
            'secret': secret,
            'otp_type': otp_type,
            'refresh_time': refresh_time,
            'company_id': company_id,
            'company': selected_company_name 
        }

        existing_otp_secrets.append(new_otp_secret)
        save_to_db(existing_otp_secrets)
        save_companies_to_db(companies_from_db)

        flash(f"New OTP secret '{name}' added successfully.")
        return redirect(url_for('home'))

    return render_template('add.html', form=form)

if __name__ == '__main__':
    port = 5001 
    logging.info(f"Server started on port {port}.")
    try:
        app.run(debug=True, port=port, host='0.0.0.0', use_reloader=False)
    except KeyboardInterrupt:
        logging.info("Server stopped.")
