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
from logging_config import my_logger

from forms.company_form import CompanyForm

app = Flask(__name__)
app.config['DATABASE'] = 'instance/otp.db' 
bcrypt = Bcrypt(app)

logger = my_logger

admin_bp = Blueprint('admin', __name__)

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

def get_all_users():
    try:
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("SELECT id, username, is_admin FROM users")
            users = cursor.fetchall()
        user_count = len(users)
        logger.info(f"Admin '{current_user.username}' fetched all users successfully. Total users: {user_count}.")
        return users
    except sqlite3.Error as e:
        logger.error(f"Error fetching all users: {e}")
        logger.warning(f"Admin '{current_user.username}' encountered an error while fetching users.")
        return []

def load_companies_from_db():
    try:
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("SELECT company_id, name, kundennummer FROM companies ORDER BY company_id")
            companies = [{'company_id': row[0], 'name': row[1], 'kundennummer': row[2]} for row in cursor.fetchall()]
        company_count = len(companies)
        logger.info(f"Admin '{current_user.username}' loaded companies from database successfully. Total companies: {company_count}.")
        return companies
    except sqlite3.Error as e:
        logger.error(f"Error loading companies from db: {e}")
        logger.warning(f"Admin '{current_user.username}' encountered an error while loading companies.")
        return []

@admin_bp.route('/reset_password', methods=['POST'])
@login_required
def reset_password():
    if not current_user.is_admin:
        flash('Unauthorized access. Only admins can reset passwords.', 'danger')
        logger.warning(f"Unauthorized password reset attempt by user '{current_user.username}'.")
        return redirect(url_for('admin.user_management'))

    data = request.get_json()
    user_id_to_reset = data.get('userIdToReset')
    new_password = data.get('new_password')

    if not user_id_to_reset or not new_password:
        flash('Missing user ID or new password.', 'warning')
        logger.warning(f"Password reset attempt with missing data by admin '{current_user.username}'.")
        return redirect(url_for('admin.user_management'))

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    try:
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id_to_reset,))
            user_record = cursor.fetchone()

            if not user_record:
                flash('User not found.', 'danger')
                logger.warning(f"Password reset failed for non-existent user ID {user_id_to_reset} by admin '{current_user.username}'.")
                return redirect(url_for('admin.user_management'))

            cursor.execute("UPDATE users SET password = ?, session_token = NULL WHERE id = ?", (hashed_password, user_id_to_reset))
            db.commit()

            flash('Password reset successfully.', 'success')
            logger.info(f"Admin '{current_user.username}' reset password for user '{user_record[0]}' (ID: {user_id_to_reset}).")
            return redirect(url_for('admin.user_management'))
    except sqlite3.Error as e:
        logger.error(f"Error resetting password for user ID {user_id_to_reset} by admin '{current_user.username}': {e}")
        flash('Failed to reset password.', 'danger')
        return redirect(url_for('admin.user_management'))

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
        logger.error(f"Error fetching admin status for user '{current_user.username}': {e}")
        return redirect(url_for('home'))

    if not is_admin:
        flash('You do not have permission to view this page.', 'error')
        logger.warning(f"Unauthorized access to user management by '{current_user.username}'.")
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
            logger.info(f"Admin '{current_user.username}' added new user '{username}'.")
        except sqlite3.Error as e:
            flash('Failed to add new user.', "error")
            logger.error(f"Error inserting new user '{username}' by admin '{current_user.username}': {e}")

        return redirect(url_for('admin.user_management'))

    users = get_all_users()
    logger.info(f"Admin '{current_user.username}' accessed user management.")
    return render_template('user_management.html', user_form=user_form, users=users)

@admin_bp.route('/company_management', methods=['GET', 'POST'])
@login_required
def company_management():
    company_form = CompanyForm()

    if company_form.validate_on_submit() and company_form.submit_company.data:
        company_name = company_form.name.data
        kundennummer = company_form.kundennummer.data
        password = company_form.password.data

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            db_path = app.config['DATABASE']
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute("""
                    INSERT INTO companies (name, kundennummer, password) 
                    VALUES (?, ?, ?)
                """, (company_name, kundennummer, hashed_password))
                db.commit()
            flash(f"New company {company_name} with Kundennummer {kundennummer} added.", "success")
            logger.info(f"Admin '{current_user.username}' added new company '{company_name}' with Kundennummer '{kundennummer}'.")
        except sqlite3.Error as e:
            flash('Failed to add new company.')
            logger.error(f"Error inserting new company '{company_name}' by admin '{current_user.username}': {e}")
            logger.debug(f"Company details: name={company_name}, kundennummer={kundennummer}, hashed_password={hashed_password}")

    is_admin = False
    try:
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE id = ?", (current_user.id,))
            is_admin = cursor.fetchone()[0]
    except sqlite3.Error as e:
        flash('Failed to fetch user admin status.', 'error')
        logger.error(f"Error fetching admin status for user '{current_user.username}': {e}")

    companies = load_companies_from_db()
    logger.info(f"Admin '{current_user.username}' accessed company management.")
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

                        cursor.execute("SELECT password FROM companies WHERE company_id = ?", (company_id,))
                        result = cursor.fetchone()
                        current_password = result[0] if result else None

                        if company_form.password.data:
                            hashed_password = bcrypt.generate_password_hash(company_form.password.data).decode('utf-8')
                        else:
                            hashed_password = current_password

                        cursor.execute("""
                            UPDATE companies SET name = ?, kundennummer = ?, password = ? WHERE company_id = ?
                        """, (company_form.name.data, company_form.kundennummer.data, hashed_password, company_id))
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
                cursor.execute("SELECT name, kundennummer, password FROM companies WHERE company_id = ?", (company_id,))
                company = cursor.fetchone()
                if company:
                    password_status = "Current password is set" if company[2] else "No current password"
                    return jsonify({'success': True, 'name': company[0], 'kundennummer': company[1], 'password_status': password_status})
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
                logger.warning(f"Unauthorized admin status toggle attempt by '{current_user.username}'.")
                flash("Only admins can toggle admin status.")
                return redirect(url_for('admin.user_management'))

            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            username = cursor.fetchone()
            if username and username[0] == "admin":
                logger.warning(f"Attempt to toggle admin status of the root admin user '{username[0]}' by '{current_user.username}'.")
                flash(f"Admin user's status cannot be toggled.", "error")
                return redirect(url_for('admin.user_management'))

            cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
            current_status = cursor.fetchone()[0]
            new_status = not current_status
            cursor.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
            db.commit()

            logger.info(f"Admin status for user '{username[0]}' (ID: {user_id}) toggled to {'enabled' if new_status else 'disabled'} by admin '{current_user.username}'.")
            flash(f"Admin status for user ID {user_id} {'enabled' if new_status else 'disabled'}.", "success")
    except sqlite3.Error as e:
        logger.error(f"Error toggling admin status for user_id {user_id} by admin '{current_user.username}': {e}")
        flash("Failed to toggle admin status.", "error")

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
    # Check if the current user is the admin
    if current_user.get_id() != "admin":
        logger.warning(f"Unauthorized company creation attempt by user '{current_user.username}'.")
        flash("Only the admin can add companies.")
        return redirect(url_for('admin.admin_settings'))

    new_company_name = request.form.get('name')
    new_kundennummer = request.form.get('kundennummer')

    try:
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("INSERT INTO companies (name, kundennummer) VALUES (?, ?)", (new_company_name, new_kundennummer))
            db.commit()
        flash(f'New company "{new_company_name}" with Kundennummer "{new_kundennummer}" added.')
        logger.info(f"Company '{new_company_name}' with Kundennummer '{new_kundennummer}' created by admin '{current_user.username}'.")
    except sqlite3.Error as e:
        flash('Failed to add new company.')
        logger.error(f"Error inserting new company '{new_company_name}' by admin '{current_user.username}': {e}")
    
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
        logger.warning(f"Unauthorized attempt to delete user ID {user_id} by '{current_user.username}'.")
        flash("Only the user 'admin' can delete other users.", "error")
        return jsonify(success=False, message="Only the admin can delete users."), 403

    try:
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            logger.info(f"Admin '{current_user.username}' is attempting to delete user ID {user_id}.")
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            if cursor.rowcount == 0:
                logger.warning(f"Attempt to delete non-existent user ID {user_id} by admin '{current_user.username}'.")
                flash("User not found.", "error")
                return jsonify(success=False, message="User not found."), 404
            logger.info(f"User ID {user_id} deleted successfully by admin '{current_user.username}'.")
            flash(f"User with ID {user_id} deleted successfully.", "info")
            return jsonify(success=True), 200
    except sqlite3.Error as e:
        logger.error(f"Error deleting user ID {user_id} by admin '{current_user.username}': {e}")
        flash("Failed to delete user.", "error")
        return jsonify(success=False, message="Failed to delete user."), 500
    
@admin_bp.route('/delete_company/<int:company_id>', methods=['POST'])
@login_required
def delete_company(company_id):
    if not current_user.is_admin:
        logger.warning(f"Unauthorized attempt to delete company ID {company_id} by '{current_user.username}'.")
        flash("You do not have permission to perform this action.", "error")
        return jsonify(success=False, message="Unauthorized access."), 403

    try:
        db_path = app.config['DATABASE']
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            logger.info(f"Admin '{current_user.username}' is attempting to delete company ID {company_id}.")
            cursor.execute("DELETE FROM companies WHERE company_id = ?", (company_id,))
            db.commit()

            if cursor.rowcount == 0:
                logger.warning(f"Attempt to delete non-existent company ID {company_id} by admin '{current_user.username}'.")
                flash("The company could not be found.", "error")
                return jsonify(success=False, message="The company does not exist."), 404

            logger.info(f"Company ID {company_id} deleted successfully by admin '{current_user.username}'.")
            flash("Company deleted successfully.", "success")
            return jsonify(success=True, message="Company deleted successfully."), 200
    except sqlite3.Error as e:
        logger.error(f"Failed to delete company ID {company_id} by admin '{current_user.username}': {e}")
        return jsonify(success=False, message="Failed to delete the company."), 500
