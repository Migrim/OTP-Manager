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
import sqlite3
import logging

logging.basicConfig(filename='MV.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
Bootstrap(app)

from admin_routes import admin_bp
app.register_blueprint(admin_bp, url_prefix='/admin')

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
                password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
            )
        """)
        db.commit()

def save_to_db(otp_secrets):
    conn = sqlite3.connect('otp.db')
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM otp_secrets")

    for otp_secret in otp_secrets:
        cursor.execute("""
        INSERT INTO otp_secrets (name, secret, otp_type, refresh_time)
        VALUES (?, ?, ?, ?)
        """, (otp_secret['name'], otp_secret['secret'], otp_secret['otp_type'], otp_secret['refresh_time']))
    
    conn.commit()
    conn.close()

def load_from_db():
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT name, secret, otp_type, refresh_time FROM otp_secrets")
        return [{'name': row[0], 'secret': row[1], 'otp_type': row[2], 'refresh_time': row[3]} for row in cursor.fetchall()]

def load_companies_from_db():
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, name FROM companies")
        return [{'id': row[0], 'name': row[1]} for row in cursor.fetchall()]

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
    name = StringField('Company Name', validators=[InputRequired(), Length(min=4, max=25)])
    submit = SubmitField('Add Company')

def get_current_user():
    return current_user

def get_all_users():
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, username FROM users")
        users = cursor.fetchall()
    return users


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
    session.pop('user_id', None)
    logging.info(f"A User was Logged out!.")
    return redirect(url_for('login'))
    

@app.route('/refresh_codes_v2')
def refresh_codes_v2():
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

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/change-password', methods=['POST'])
def change_password():
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    
    if not user_id or not new_password:
        flash('Benutzer-ID oder Passwort fehlt!')
        logging.error(f"The Operation %Change Password% failed for user_id {user_id}!")
        return redirect(url_for('home'))

    hashed_password = generate_password_hash(new_password, method='sha256')
    
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            db.commit()
        logging.info(f"Password for user_id {user_id} has been sucessfully changed.")
        flash('Passwort erfolgreich geändert!')
    except sqlite3.Error as e:
        flash('Es gab ein Problem beim Ändern des Passworts!')
        logging.error(f"Error updating password for user_id {user_id}: {e}")
    
    return redirect(url_for('home'))

@app.route('/profile')
def profile():
    print("Profile function executed.")
    if current_user.is_authenticated:
        print("User is authenticated.")
        return make_response(render_template('profile.html', username=current_user.username))
    else:
        print("User is not authenticated.")  
        return make_response(redirect(url_for('login')))

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

    if user and check_password_hash(user[2], password):
        session['user_id'] = user[0]
        flash('Successfully logged in!')
        logging.info(f"User: {username} Logged in!")

        user_obj = UserMixin()
        user_obj.id = user[0]
        user_obj.username = user[1]
        login_user(user_obj)

        return redirect(url_for('profile')) 
    else:
        flash('Invalid credentials!')
        logging.error(f"Login Failed. Invalid credentials!")


    return render_template('login.html')

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
    otp_secrets = load_from_db()
    otp_codes = []

    if form.validate_on_submit():
        logging.info('Form validated.')
        otp_secrets.append({
            'name': form.name.data,
            'secret': form.secret.data,
            'otp_type': form.otp_type.data,
            'refresh_time': form.refresh_time.data
        })
        save_to_db(otp_secrets)
        form.name.data = ''
        form.secret.data = ''
        form.otp_type.data = ''
        form.refresh_time.data = ''
        logging.info(f'OTP secret added: {otp_secrets[-1]}')
        return redirect(url_for('home'))

    for otp in otp_secrets:
        otp_code = generate_otp_code(otp)
        if otp_code is None:
            flash('Invalid OTP secret')
            continue
        otp_codes.append(otp_code)

    return render_template('home.html', form=form, otp_codes=otp_codes)

@app.route('/get_logs', methods=['GET'])
@login_required
def get_logs():
    num_lines = request.args.get('lines', 10, type=int)

    with open('MV.log', 'r') as f:
        lines = f.readlines()

    output = "".join(lines[-num_lines:])
    
    return jsonify({"logs": output})

@app.route('/view_logs', methods=['GET'])
def view_logs():
    return render_template('logs.html')

@app.route('/search_form', methods=['GET'])
def search_form():
    return render_template('search_form.html')

@app.errorhandler(404)
def page_not_found(e):
    logging.debug("User got the Error 404")
    return render_template('404.html'), 404

@app.route('/search', methods=['GET'])
@login_required
def search():
    return render_template('search.html')

@app.route('/edit/<name>', methods=['GET', 'POST'])
@login_required
def edit(name):
    otp_secrets = load_from_db()
    for i, otp in enumerate(otp_secrets):
        if otp['name'] == name:
            form = OTPForm()
            if request.method == 'POST':
                if form.validate():
                    logging.info(f"Form is valid. Updating OTP with name: {name}")
                    otp_secrets[i]['name'] = form.name.data
                    otp_secrets[i]['secret'] = form.secret.data
                    otp_secrets[i]['otp_type'] = form.otp_type.data
                    otp_secrets[i]['refresh_time'] = form.refresh_time.data

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
                return render_template('edit.html', form=form, name=name)
    flash('Secret Not Found')
    logging.error(f"OTP with name {name} not found.")
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
    current_user = get_current_user()

    if current_user and current_user[1] == "admin":
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
        flash('User deleted successfully.')
        return redirect(url_for('admin_settings'))
    else:
        flash('Only admin can delete users.')
        return redirect(url_for('home'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = OTPForm()
    form.company.choices = [(company['id'], company['name']) for company in load_companies_from_db()]

    if form.validate_on_submit():
        name = form.name.data
        secret = form.secret.data
        otp_type = form.otp_type.data.lower()
        refresh_time = form.refresh_time.data
        company_id = form.company.data

        if otp_type not in ['totp', 'hotp']:
            flash('Invalid OTP type. Choose either TOTP or HOTP.')
            return redirect(url_for('add'))

        new_otp_secret = {
            'name': name,
            'secret': secret,
            'otp_type': otp_type,
            'refresh_time': refresh_time,
            'company_id': company_id
        }

        existing_otp_secrets = load_from_db()

        existing_otp_secrets.append(new_otp_secret)

        save_to_db(existing_otp_secrets)
        return redirect(url_for('home'))

    return render_template('add.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)