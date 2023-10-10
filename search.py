from flask import Flask, request, render_template, json
import base64
from pyotp import totp, hotp
from flask import Blueprint, redirect, url_for
import sqlite3
from flask import session
from math import ceil

search_blueprint = Blueprint('search_blueprint', __name__)
app = Flask(__name__)
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
                companies.name AS company_name,
                companies.kundennummer AS company_kundennummer
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
                'company_kundennummer': row[6]
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
    with sqlite3.connect("otp.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name FROM companies")
        return [{'company_id': row[0], 'name': row[1]} for row in cursor.fetchall()]

def get_companies_list():
    otp_secrets = load_from_db()
    companies = {otp['company'] for otp in otp_secrets if 'company' in otp}
    return companies

@search_blueprint.route('/search_otp', methods=['GET'])
def search_otp():
    query = request.args.get('name', '').lower()
    selected_company = request.args.get('company', 'All Companies')

    otp_secrets = load_from_db()

    matched_secrets = []

    for otp_secret in otp_secrets:
        stored_name = otp_secret.get('name', 'Unnamed').lower()
        stored_kundennummer = str(otp_secret.get('company_kundennummer', '')).lower()
        stored_company = otp_secret.get('company', 'Unbekannt')

        if (selected_company == 'All Companies' or selected_company == stored_company):
            if query in stored_name or query in stored_kundennummer:
                if otp_secret['otp_type'] == 'totp':
                    if not is_base32(otp_secret['secret']):
                        return 'Invalid base32 secret', 400
                    otp_maker = totp.TOTP(otp_secret['secret'])
                    otp_secret['otp_code'] = otp_maker.now()
                elif otp_secret['otp_type'] == 'hotp':
                    hotp_maker = hotp.HOTP(otp_secret['secret'])
                    otp_secret['otp_code'] = hotp_maker.at(0)
                matched_secrets.append(otp_secret)

    if matched_secrets:
        return render_template('otp.html', matched_secrets=matched_secrets)
    else:
        return 'No matches found', 404

if __name__ == '__main__':
    app.run(debug=True)
