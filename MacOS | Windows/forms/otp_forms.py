from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import InputRequired, Length, Email, Optional, DataRequired
from wtforms.widgets import HiddenInput

class OTPForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=25, message="Der Name darf nicht länger als 25 Zeichen sein.")])
    email = StringField('Email', validators=[Optional(), Email(message='Invalid email address.')])
    secret = StringField('Secret', validators=[InputRequired()])
    otp_type = SelectField('OTP Type', validators=[InputRequired()], choices=[('totp', 'TOTP'), ('hotp', 'HOTP')])
    refresh_time = IntegerField('Refresh Time', default=30, render_kw={"disabled": "disabled"})
    refresh_time_hidden = StringField(widget=HiddenInput(), default=30)
    company = SelectField('Company', validators=[InputRequired()], choices=[])
    submit = SubmitField('Submit')