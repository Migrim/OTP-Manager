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
import subprocess 
import sqlite3
import logging
import re
import uuid

logging.basicConfig(filename='MV.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
my_logger = logging.getLogger('MV_logger')

app = Flask(__name__)
start_time = datetime.now()
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
Session(app)
Bootstrap(app)

from admin_routes import admin_bp
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(search_blueprint)

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
            return user
        return None

def init_db():
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
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
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                last_login_time TEXT,
                session_token TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kundennummer TEXT
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
        db.commit()

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
        INSERT INTO companies (name)
        VALUES (?)
        """, (company['name'],))

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
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Add User')

class CompanyForm(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired()])
    kundennummer = StringField('Kundennummer', validators=[DataRequired()])
    submit_company = SubmitField('Add Company')

def get_current_user():
    return current_user

def get_all_users():
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, username FROM users")
        users = cursor.fetchall()
    return users

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
    session.pop('session_token', None)

    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("UPDATE users SET session_token = NULL WHERE id = ?", (user_id,))
        db.commit()

    return redirect(url_for('login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        session_token = session.get('session_token')

        if not user_id or not session_token:
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
            continue
        otp_codes.append({
            'name': otp['name'],
            'otp_code': otp_code['otp_code']
        })

    return jsonify({"otp_codes": otp_codes})

@app.route('/reset/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if not new_password:
            flash('Passwort fehlt!')
            return render_template('reset_password.html', user_id=user_id)
        
        hashed_password = generate_password_hash(new_password, method='sha256')
        
        try:
            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
                db.commit()
            flash('Passwort erfolgreich geändert!')
        except sqlite3.Error as e:
            flash('Es gab ein Problem beim Ändern des Passworts!')
        
        return redirect(url_for('home'))
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
    user = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        keep_logged_in = 'keep_logged_in' in request.form

        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            update_statistics(logins=1)
            session_token = str(uuid.uuid4())
            session['user_id'] = user[0]
            session['session_token'] = session_token

            if keep_logged_in:
                session.permanent = True 
            else:
                session.permanent = False

            flash('Successfully logged in!')
            my_logger.info(f"User: {username} Logged in!")

            last_login_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute("UPDATE users SET last_login_time = ? WHERE id = ?", (last_login_time, user[0]))
                db.commit()

            user_obj = UserMixin()
            user_obj.id = user[0]
            user_obj.username = user[1]
            login_user(user_obj)

            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute("UPDATE users SET session_token = ? WHERE id = ?", (session_token, user[0]))
                db.commit()

            return redirect(url_for('profile'))
        else:
            flash('Die Zugangsdaten konnten nicht validiert werden!')
            my_logger.warning(f"Failed login attempt for user: {username}")

    return render_template('login.html')

@app.route('/profile')
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
    ping_time, speed = get_ping_time("google.com")
    
    return render_template(
        'about.html',
        stored_otps=stored_otps,
        logins_today=logins_today,
        times_refreshed=times_refreshed,
        uptime=uptime,
        ping_time=ping_time,
        speed=speed,
        last_user_login_time=last_user_login_time,  
        current_server_time=current_server_time,
        older_stats=older_stats
    )

def get_uptime():
    current_time = datetime.now()
    uptime = current_time - start_time

    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    return f"{days} Days {hours}h:{minutes}m:{seconds}s"

def get_ping_time(host):
    try:
        response = subprocess.check_output(
            ["ping", "-c", "1", host],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        time = response.split("time=")[1].split(" ")[0]
        speed = response.split("bytes from")[1].split(": icmp_seq=")[0]
        
        return f"{time} ms", speed
    except Exception as e:
        return "failed", "Unknown"

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

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    form = OTPForm()
    otp_secrets = session.get('filtered_secrets', load_from_db())
    otp_codes = []
    items_per_page = 9

    page = request.args.get('page', type=int, default=1)

    if form.validate_on_submit():
        logging.info('Form validated.')
        otp_secrets.append({
            'name': form.name.data,
            'company': form.company.data if form.company.data else 'N/A',
            'secret': form.secret.data,
            'otp_type': form.otp_type.data,
            'refresh_time': form.refresh_time.data
        })
        save_to_db(otp_secrets)
        form.name.data = ''
        form.company.data = ''
        form.secret.data = ''
        form.otp_type.data = ''
        form.refresh_time.data = ''
        logging.info(f'OTP secret added: {otp_secrets[-1]}')
        return redirect(url_for('home'))

    companies = load_companies_from_db()
    selected_company = request.args.get('company')

    if selected_company:
        otp_secrets = [otp for otp in otp_secrets if otp['company'] == selected_company]

    for otp in otp_secrets:
        otp_code = generate_otp_code(otp)
        if otp_code is None:
            flash('Invalid OTP secret')
            continue
        otp_code['company'] = otp.get('company', 'Unbekannt')
        otp_codes.append(otp_code)

    total_pages = ceil(len(otp_codes) / items_per_page)
    start_index = (page - 1) * items_per_page
    end_index = start_index + items_per_page

    displayed_otp_codes = otp_codes[start_index:end_index]

    search_name = request.args.get('name')

    return render_template('home.html', form=form, otp_codes=displayed_otp_codes, companies=companies, search_name=search_name, page=page, total_pages=total_pages)

@app.route('/get_logs', methods=['GET'])
@login_required
def get_logs():
    num_lines = request.args.get('lines', 10, type=int)

    with open('MV.log', 'r') as f:
        lines = f.readlines()

    output = "".join(lines[-num_lines:])
    
    return jsonify({"logs": output})

@app.route('/view_logs')
def view_logs():
    with open("mv.log", "r") as f:
        logs = f.read()
    return render_template('logs.html', logs=logs)

@app.route('/search_form', methods=['GET'])
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
    all_secrets = fetch_all_secrets()
    
    matched_secrets = [secret for secret in all_secrets if query.lower() in secret['name'].lower()]
    
    print(matched_secrets)
    return render_template('otp.html', otp_secrets=matched_secrets)

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

@app.route('/delete_secret/<name>', methods=['POST'])
@login_required
def delete_secret(name):
    try:
        with sqlite3.connect('otp.db') as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM otp_secrets WHERE name = ?", (name,))
            conn.commit()
        flash(f'Successfully deleted secret with name: {name}', 'success')
    except sqlite3.Error as e:
        flash(f'Could not delete secret: {e}', 'danger')
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

        if not name or not secret:
            flash('Name and secret fields cannot be empty.')
            logging.warning(f"User '{current_user.username}' attempted to add an OTP with empty name or secret.")
            return redirect(url_for('add'))

        if otp_type not in ['totp', 'hotp']:
            flash('Invalid OTP type. Choose either TOTP or HOTP.')
            logging.error(f"User '{current_user.username}' submitted an invalid OTP-Type in the /add form.")
            return redirect(url_for('add'))
        
        if len(secret) < 16:
            flash('Secret is too short. It should be at least 16 characters.')
            logging.warning(f"User '{current_user.username}' attempted to add an OTP with a too short secret.")
            return redirect(url_for('add'))
        
        if not secret.isalnum():
            flash('Secret must contain only alphanumeric characters.')
            logging.warning(f"User '{current_user.username}' attempted to add an OTP with a secret containing special characters.")
            return redirect(url_for('add'))

        if not isinstance(refresh_time, int) or refresh_time <= 0:
            flash('Refresh time must be a positive number.')
            logging.warning(f"User '{current_user.username}' attempted to add an OTP with invalid refresh time.")
            return redirect(url_for('add'))

        valid_base32 = re.fullmatch('[A-Z2-7=]{16,}', secret, re.IGNORECASE)
        if not valid_base32 or len(secret) % 8 != 0:
            flash('Secret must be a valid base32 string with a length that is a multiple of 8 characters.')
            logging.warning(f"User '{current_user.username}' attempted to add an OTP with an invalid secret.")
            return redirect(url_for('add'))

        suspicious_pattern = re.compile(r'(--|;|--|;|/\*|\*/|@@|@|char|nchar|varchar|nvarchar|alter|begin|cast|create|cursor|declare|delete|drop|end|exec|execute|fetch|insert|kill|open|select|sys|sysobjects|syscolumns|table|update)', re.IGNORECASE)
        if suspicious_pattern.search(name) or suspicious_pattern.search(secret):
            flash('Suspicious patterns detected in input fields.')
            logging.warning(f"User '{current_user.username}' attempted to add an OTP with suspicious patterns in input fields.")
            return redirect(url_for('add'))

        selected_company_name = next((company['name'] for company in companies_from_db if company['company_id'] == company_id), 'N/A')

        existing_otp_secrets = load_from_db()
        if any(secret['name'] == name for secret in existing_otp_secrets):
            flash('A secret with this name already exists. Please choose a different name.')
            logging.warning(f"User '{current_user.username}' attempted to add an OTP with a duplicate name.")
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
    logging.info("Server started.")
    app.run(debug=True, port=5001, host='0.0.0.0', use_reloader=False)
