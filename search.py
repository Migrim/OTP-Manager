from flask import Flask, request, render_template, json
import base64
from pyotp import totp, hotp

app = Flask(__name__)

def load_from_json(filename='otp_secrets.json'):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def is_base32(secret):
    try:
        base64.b32decode(secret)
        return True
    except:
        return False

@app.route('/search_otp', methods=['GET'])
def search_otp():
    name = request.args.get('name').lower() 
    otp_secrets = load_from_json()
    
    matched_secrets = []
    
    for otp_secret in otp_secrets:
        stored_name = otp_secret.get('name', 'Unnamed').lower() 
        if name in stored_name:  
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
        return render_template('otp.html', otp_secrets=matched_secrets)
    else:

        return redirect(url_for('home.html'))


if __name__ == '__main__':
    app.run(debug=True)
