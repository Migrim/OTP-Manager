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
app.config['DATABASE'] = 'instance/otp.db' 
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
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
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
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("SELECT company_id, name, kundennummer FROM companies ORDER BY company_id")
            return [{'company_id': row[0], 'name': row[1], 'kundennummer': row[2]} for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Error loading companies from db: {e}")
        return []

@admin_bp.route('/admin/reset_password', methods=['POST'])
@login_required
def reset_password():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized access. Only admins can reset passwords.'}), 403

    data = request.get_json()
    user_id_to_reset = data.get('userIdToReset')
    new_password = data.get('new_password')

    if not user_id_to_reset or not new_password:
        return jsonify({'success': False, 'message': 'Missing user ID or new password.'}), 400

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    try:
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id_to_reset))
            db.commit()

            if cursor.rowcount == 0:
                return jsonify({'success': False, 'message': 'User not found.'}), 404

            return jsonify({'success': True, 'message': 'Password reset successfully.'})
    except sqlite3.Error as e:
        logger.error(f"Error resetting password for user {user_id_to_reset}: {e}")
        return jsonify({'success': False, 'message': 'Failed to reset password.'}), 500

@admin_bp.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    is_admin = False
    try:
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
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
            db_path = app.config['DATABASE'] 
            with sqlite3.connect(db_path) as db:
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
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
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
            db_path = app.config['DATABASE'] 
            with sqlite3.connect(db_path) as db:
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
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            if company_form.validate_on_submit():
                try:
                    db_path = app.config['DATABASE'] 
                    with sqlite3.connect(db_path) as db:
                        cursor = db.cursor()
                        cursor.execute("UPDATE companies SET name = ?, kundennummer = ? WHERE company_id = ?",
                                       (company_form.name.data, company_form.kundennummer.data, company_id))
                        db.commit()
                    return jsonify({'success': True, 'message': 'Company details updated successfully.'})
                except sqlite3.Error as e:
                    print(f"Error updating company details: {e}")
                    return jsonify({'success': False, 'message': 'Failed to update company details.'}), 500
            else:
                return jsonify({'success': False, 'message': 'Form validation failed.'}), 400

    else: 
        try:
            db_path = app.config['DATABASE'] 
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute("SELECT name, kundennummer FROM companies WHERE company_id = ?", (company_id,))
                company = cursor.fetchone()
                if company:
                    return jsonify({'success': True, 'name': company[0], 'kundennummer': company[1]})
                else:
                    return jsonify({'success': False, 'message': 'Company not found.'}), 404
        except sqlite3.Error as e:
            print(f"Error retrieving company details: {e}")
            return jsonify({'success': False, 'message': 'Failed to retrieve company details.'}), 500

@admin_bp.route('/toggle_admin/<int:user_id>', methods=['GET'])
@login_required
def toggle_admin(user_id):
    try:
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE username = ?", (current_user.username,))
            is_current_user_admin = cursor.fetchone()[0]
            if not is_current_user_admin:
                flash("Only admins can toggle admin status.")
                return redirect(url_for('admin.user_management'))

            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            username = cursor.fetchone()
            if username and username[0] == "admin":
                flash(f"Admin user's status cannot be toggled.", "error")
                return redirect(url_for('admin.user_management'))

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
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE id = ?", (current_user.id,))
            is_admin = bool(cursor.fetchone()[0])
    except sqlite3.Error as e:
        flash('Failed to fetch admin status.')
        logging.error(f"Error fetching admin status: {e}")

    return render_template('admin_settings.html', is_admin=is_admin)

@admin_bp.route('/add_company', methods=['POST'])
@login_required
def add_company():
    if current_user.get_id() != "admin":
        flash("Only the admin can add companies.")
        return redirect(url_for('admin.admin_settings'))

    new_company_name = request.form.get('name')
    new_kundennummer = request.form.get('kundennummer')
    try:
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("INSERT INTO companies (name, kundennummer) VALUES (?, ?)", (new_company_name, new_kundennummer))  # Modified Line
            db.commit()
        flash(f'New company "{new_company_name}" with Kundennummer "{new_kundennummer}" added.')
        logger.info(f"Company '{new_company_name}' with Kundennummer '{new_kundennummer}' created by '{current_user.username}'.")  # Modified Line
    except sqlite3.Error as e:
        flash('Failed to add new company.')
        logger.error(f"Error inserting new company: {e}")
    return redirect(url_for('admin.admin_settings'))

@admin_bp.route('/add_search_terms/<int:company_id>', methods=['GET'])
@login_required
def add_search_terms(company_id):
    if current_user.username != "admin":
        flash("Only the admin can add search terms.")
        return redirect(url_for('admin.admin_settings'))

    return redirect(url_for('admin.admin_settings'))

@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.username != "admin":
        flash("Only the admin can delete users.")
        return jsonify(success=False, message="Only the admin can delete users."), 403

    try:
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            print(f"Attempting to delete user with ID: {user_id}")
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            print(f"User with ID: {user_id} deleted successfully.")
            return jsonify(success=True), 200
    except sqlite3.Error as e:
        print(f"Error deleting user with ID {user_id}: {e}")
        return jsonify(success=False, message="Failed to delete user."), 500
    
@admin_bp.route('/delete_company/<int:company_id>', methods=['POST'])
@login_required
def delete_company(company_id):
    if not current_user.is_admin:
        flash("You do not have permission to perform this action.", "error")
        return jsonify(success=False, message="Unauthorized access."), 403

    try:
        db_path = app.config['DATABASE'] 
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM companies WHERE company_id = ?", (company_id,))
            db.commit()
            
            if cursor.rowcount == 0:
                flash("The company could not be found.", "error")
                return jsonify(success=False, message="The company does not exist."), 404

            flash("Company deleted successfully.", "success")
            return jsonify(success=True, message="Company deleted successfully."), 200
    except sqlite3.Error as e:
        logger.error(f"Failed to delete company {company_id}: {e}")
        return jsonify(success=False, message="Failed to delete the company."), 500
