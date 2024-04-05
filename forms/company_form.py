from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import InputRequired, Length, Email, Optional, DataRequired

class CompanyForm(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired()], render_kw={"placeholder": "Enter company name"})
    kundennummer = StringField('Kundennummer', validators=[DataRequired()], render_kw={"placeholder": "Enter Kundennummer"})
    submit_company = SubmitField('Add Company')