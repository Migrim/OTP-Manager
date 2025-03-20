from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import InputRequired, Length, Email, Optional, DataRequired

class CompanyForm(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired()])
    kundennummer = StringField('Kundennummer', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit_company = SubmitField('Add Company')