import flask
from flask import Blueprint, Flask, render_template, flash, redirect, url_for, request, logging
from flask_login import login_required, current_user, LoginManager
from werkzeug.security import generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask import jsonify
from flask_bcrypt import Bcrypt
import bcrypt
import sqlite3
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
bcrypt = Bcrypt(app)

logger = logging.getLogger('mv_admin_logger')
logger.setLevel(logging.DEBUG)

log_file = 'MV.log'
file_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=10)
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

admin_bp = Blueprint('admin', __name__)

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class CompanyForm(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired()])
    kundennummer = StringField('Kundennummer', validators=[DataRequired()])
    submit_company = SubmitField('Add Company')

def get_all_users():
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT id, username, is_admin FROM users")
            users = cursor.fetchall()
        logger.info("Fetched all users successfully.")
        return users
    except sqlite3.Error as e:
        logger.error(f"Error fetching all users: {e}")
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

@admin_bp.route('/admin/reset_password', methods=['POST'])
@login_required
def reset_password():
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            db.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    is_admin = False
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE id = ?", (current_user.id,))
            is_admin = cursor.fetchone()[0]
    except sqlite3.Error as e:
        flash('Failed to fetch user admin status.', 'error')
        logger.error(f"Error fetching user admin status: {e}")
        return redirect(url_for('home'))  

    if not is_admin:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))  

    user_form = UserForm()

    if user_form.validate_on_submit():
        username = user_form.username.data
        password = user_form.password.data

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        try:
            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                db.commit()
            flash(f"New user {username} added successfully.", "success")
        except sqlite3.Error as e:
            flash('Failed to add new user.', "error")
            logging.error(f"Error inserting new user: {e}")

        return redirect(url_for('admin.user_management'))

    users = get_all_users()
    return render_template('user_management.html', user_form=user_form, users=users)

@admin_bp.route('/company_management', methods=['GET', 'POST'])
@login_required
def company_management():
    company_form = CompanyForm()

    is_admin = False
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE username = ?", (current_user.username,))
            result = cursor.fetchone()
            if result:
                is_admin = bool(result[0])
    except sqlite3.Error as e:
        flash('Failed to fetch user admin status.')
        logger.error(f"Error fetching user admin status: {e}")

    if company_form.validate_on_submit() and company_form.submit_company.data:
        company_name = company_form.name.data
        kundennummer = company_form.kundennummer.data

        try:
            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                cursor.execute("INSERT INTO companies (name, kundennummer) VALUES (?, ?)", (company_name, kundennummer))
                db.commit()
            flash(f"New company {company_name} with Kundennummer {kundennummer} added.", "success")
        except sqlite3.Error as e:
            flash('Failed to add new company.')
            logger.error(f"Error inserting new company: {e}")

    companies = load_companies_from_db()
    
    return render_template('company_management.html', company_form=company_form, companies=companies, is_admin=is_admin)

@admin_bp.route('/edit_company/<int:company_id>', methods=['GET', 'POST'])
@login_required
def edit_company(company_id):
    company_form = CompanyForm()

    if request.method == 'POST':
        if company_form.validate_on_submit():
            try:
                with sqlite3.connect("otp.db") as db:
                    cursor = db.cursor()
                    cursor.execute("UPDATE companies SET name = ?, kundennummer = ? WHERE id = ?",
                                   (company_form.name.data, company_form.kundennummer.data, company_id))
                    db.commit()
                flash("Company details updated successfully.", "success")
            except sqlite3.Error as e:
                flash("Failed to update company details.", "error")
                logger.error(f"Error updating company details: {e}")
            return redirect(url_for('admin.company_management'))
    else:
        try:
            with sqlite3.connect("otp.db") as db:
                cursor = db.cursor()
                # Fetch the existing company details
                cursor.execute("SELECT name, kundennummer FROM companies WHERE id = ?", (company_id,))
                company = cursor.fetchone()
                if company:
                    # Populate the form with the existing company details
                    company_form.name.data = company[0]
                    company_form.kundennummer.data = company[1]
                else:
                    flash("Company not found.", "error")
                    return redirect(url_for('admin.company_management'))
        except sqlite3.Error as e:
            flash("Failed to retrieve company details.", "error")
            logger.error(f"Error retrieving company details: {e}")
            return redirect(url_for('admin.company_management'))

    return render_template('edit_company.html', company_form=company_form, company_id=company_id)

@admin_bp.route('/toggle_admin/<int:user_id>', methods=['GET'])
@login_required
def toggle_admin(user_id):
    if current_user.username != "admin":
        flash("Only the admin can toggle admin status.")
        return redirect(url_for('admin.user_management'))

    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
            current_status = cursor.fetchone()[0]
            new_status = not current_status
            cursor.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
            db.commit()
        flash(f"Admin status for user ID {user_id} {'enabled' if new_status else 'disabled'}.", "success")
    except sqlite3.Error as e:
        flash("Failed to toggle admin status.", "error")
        logger.error(f"Error toggling admin status for user_id {user_id}: {e}")

    return redirect(url_for('admin.user_management'))

@admin_bp.route('/admin_settings', methods=['GET', 'POST'])
@login_required
def admin_settings():

    is_admin = False
    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE id = ?", (current_user.id,))
            is_admin = bool(cursor.fetchone()[0])
    except sqlite3.Error as e:
        flash('Failed to fetch admin status.')
        logging.error(f"Error fetching admin status: {e}")

    return render_template('admin_settings.html', is_admin=is_admin)

@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.username != "admin":
        return jsonify({"success": False, "message": "Only the admin can delete users."}), 403

    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
        return jsonify({"success": True, "message": "User successfully deleted."})
    except sqlite3.Error as e:
        logger.error(f"Error deleting user with user_id {user_id}: {e}")
        return jsonify({"success": False, "message": "Failed to delete user."}), 500

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

    return redirect(url_for('admin.admin_settings'))

@admin_bp.route('/delete_company/<int:company_id>', methods=['POST'])
@login_required
def delete_company(company_id):
    if current_user.username != "admin":
        flash("Only the admin can delete companies.")
        return redirect(url_for('admin.company_management'))

    try:
        with sqlite3.connect("otp.db") as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM companies WHERE id = ?", (company_id,))  # Ensure column name matches your DB schema
            db.commit()
        flash('Company deleted successfully!')
    except sqlite3.Error as e:
        flash('Failed to delete company.')
        logger.error(f"Error deleting company with id {company_id}: {e}")
    return redirect(url_for('admin.company_management'))

