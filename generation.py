from pyotp import TOTP, HOTP
import sqlite3
import base64

def is_base32(secret):
    try:
        base64.b32decode(secret, True) 
        return True
    except:
        return False

def generate_otp_code(otp_secret):
    if not is_base32(otp_secret.get('secret', '')):
        return None

    otp_code = None

    if otp_secret.get('otp_type') == 'totp':
        otp_maker = TOTP(otp_secret['secret'])
        otp_code = otp_maker.now()

    return {
        'name': otp_secret.get('name', ''),
        'secret': otp_secret.get('secret', ''),
        'otp_type': otp_secret.get('otp_type', ''),
        'otp_code': otp_code,
        'refresh_time': otp_secret.get('refresh_time', 30)  
    }