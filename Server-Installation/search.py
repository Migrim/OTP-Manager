from flask import Flask, request, render_template, json, flash, get_flashed_messages
import base64
from pyotp import totp, hotp
from flask import Blueprint, redirect, url_for
import sqlite3
from flask import session
from math import ceil

search_blueprint = Blueprint('search_blueprint', __name__)
app = Flask(__name__)
app.config['DATABASE'] = 'instance/otp.db' 
def load_from_db():
    db_path = app.config['DATABASE'] 
    with sqlite3.connect(db_path) as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT 
                otp_secrets.name, 
                otp_secrets.secret, 
                otp_secrets.otp_type, 
                otp_secrets.refresh_time, 
                otp_secrets.company_id, 
                companies.name AS company_name,
                companies.kundennummer AS company_kundennummer,
                otp_secrets.email AS email
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
                'company': row[5] if row[5] else 'Unbekannt',
                'company_kundennummer': row[6],
                'email': row[7]  
            } 
            for row in cursor.fetchall()
        ]

def is_base32(secret):
    try:
        base64.b32decode(secret)
        return True
    except:
        return False

def load_companies_from_db():
    db_path = app.config['DATABASE'] 
    with sqlite3.connect(db_path) as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name FROM companies")
        return [{'company_id': row[0], 'name': row[1]} for row in cursor.fetchall()]

def get_companies_list():
    otp_secrets = load_from_db()
    companies = {otp['company'] for otp in otp_secrets if 'company' in otp}
    return companies

@app.route('/flash-copied', methods=['POST'])
def flash_copied():
    data = request.get_json()
    flash(data['message'])
    return '', 200

@search_blueprint.route('/search_otp', methods=['GET'])
def search_otp():
    query = request.args.get('name', '').lower()
    selected_company = request.args.get('company', 'All Companies')

    otp_secrets = load_from_db()
    companies = load_companies_from_db()  # Load companies here!

    matched_secrets = []
    display_query = query if query else selected_company if selected_company != 'All Companies' else ''

    for otp_secret in otp_secrets:
        stored_name = otp_secret.get('name', 'Unnamed').lower()
        stored_kundennummer = str(otp_secret.get('company_kundennummer', '')).lower()
        stored_company = otp_secret.get('company', 'Unbekannt').lower()
        stored_email = otp_secret.get('email', '').lower()  

        if (selected_company.lower() == 'All Companies'.lower() or selected_company.lower() == stored_company.lower()):
            if query in stored_name or query in stored_kundennummer or query in stored_company or query in stored_email:
                if otp_secret['otp_type'] == 'totp':
                    if not is_base32(otp_secret['secret']):
                        return 'Invalid base32 secret', 400
                    otp_maker = totp.TOTP(otp_secret['secret'])
                    otp_secret['otp_code'] = otp_maker.now()
                elif otp_secret['otp_type'] == 'hotp':
                    hotp_maker = hotp.HOTP(otp_secret['secret'])
                    otp_secret['otp_code'] = hotp_maker.at(0)
                matched_secrets.append(otp_secret)

    return render_template('otp.html', matched_secrets=matched_secrets, search_query=display_query, total_results=len(matched_secrets), selected_company=selected_company, companies=companies)

if __name__ == '__main__':
    app.run(debug=True)
