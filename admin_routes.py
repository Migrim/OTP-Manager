import flask
from flask import Blueprint, render_template, flash, redirect, url_for, request, logging
from flask_login import login_required, current_user, LoginManager
from werkzeug.security import generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import sqlite3
import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger('mv_admin_logger')
logger.setLevel(logging.DEBUG)

log_file = 'mv_admin.log'
file_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=10)
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

admin_bp = Blueprint('admin', __name__)

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class CompanyForm(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired()])
    kundennummer = StringField('Kundennummer', validators=[DataRequired()])  # Add this line
    submit_company = SubmitField('Add Company')

def get_all_users():
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()
        return users
    except sqlite3.Error as e:
        logging.error(f"Error fetching all users: {e}")
        return []

def load_companies_from_db():
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM companies")
            companies = cursor.fetchall()
            companies = [{"company_id": company[0], "name": company[1]} for company in companies] 
        return companies
    except sqlite3.Error as e:
        return []

@admin_bp.route('/admin_settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    
    user_form = UserForm()
    company_form = CompanyForm()
    
    if user_form.validate_on_submit() and user_form.submit.data:
        username = user_form.username.data
        password = user_form.password.data
        hashed_password = generate_password_hash(password, method='sha256')
        
        try:
            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                db.commit()
            flash(f"New user {username} added.")
        except sqlite3.Error as e:
            flash('Failed to add new user.')
            logging.error(f"Error inserting new user: {e}")

        return redirect(url_for('admin.admin_settings'))

    if company_form.validate_on_submit() and company_form.submit_company.data:
        company_name = company_form.name.data
        kundennummer = company_form.kundennummer.data
        try:
            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute("INSERT INTO companies (name, kundennummer) VALUES (?, ?)", (company_name, kundennummer))
                db.commit()
            flash(f"New company {company_name} with Kundennummer {kundennummer} added.")
        except sqlite3.Error as e:
            flash('Failed to add new company.')
            logging.error(f"Error inserting new company: {e}")
        return redirect(url_for('admin.admin_settings'))

    users = get_all_users()
    companies = load_companies_from_db()
    is_admin = (current_user.username == "admin") 
    return render_template('admin_settings.html', user_form=user_form, company_form=company_form, users=users, companies=companies, is_admin=is_admin)

@admin_bp.route('/delete_user/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):
    if current_user.username != "admin":
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

@admin_bp.route('/add_company', methods=['POST'])
@login_required
def add_company():
    if current_user.get_id() != "admin":
        flash("Only the admin can add companies.")
        return redirect(url_for('admin.admin_settings'))

    new_company_name = request.form.get('name')
    new_kundennummer = request.form.get('kundennummer')
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("INSERT INTO companies (name, kundennummer) VALUES (?, ?)", (new_company_name, new_kundennummer))  # Modified Line
            db.commit()
        flash(f'New company "{new_company_name}" with Kundennummer "{new_kundennummer}" added.')
        logger.info(f"Company '{new_company_name}' with Kundennummer '{new_kundennummer}' created by '{current_user.username}'.")  # Modified Line
    except sqlite3.Error as e:
        flash('Failed to add new company.')
        logger.error(f"Error inserting new company: {e}")
    return redirect(url_for('admin.admin_settings'))

@admin_bp.route('/rename_company/<int:company_id>', methods=['GET', 'POST'])
@login_required
def rename_company(company_id):
    if current_user.get_id() != "admin":
        flash("Only the admin can rename companies.")
        return redirect(url_for('admin.admin_settings'))

    if request.method == 'POST':
        new_name = request.form.get('new_name')

        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("UPDATE companies SET name = ? WHERE id = ?", (new_name, company_id))
            db.commit()

        flash('Company name updated!')
        return redirect(url_for('admin.admin_settings'))

    return render_template('rename_company.html', company_id=company_id)

@admin_bp.route('/add_search_terms/<int:company_id>', methods=['GET'])
@login_required
def add_search_terms(company_id):
    if current_user.username != "admin":
        flash("Only the admin can add search terms.")
        return redirect(url_for('admin.admin_settings'))

    # Your logic here for adding search terms.
    # For demonstration, redirecting to the same admin settings page.

    return redirect(url_for('admin.admin_settings'))


@admin_bp.route('/delete_company/<int:company_id>', methods=['POST'])
@login_required
def delete_company(company_id):
    if current_user.username != "admin": 
        flash("Only the admin can delete companies.")
        return redirect(url_for('admin.admin_settings'))

    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM companies WHERE company_id = ?", (company_id,))
            db.commit()
        flash('Company deleted!')
    except sqlite3.Error as e:
        flash('Failed to delete company.')

    return redirect(url_for('admin.admin_settings'))
