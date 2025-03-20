from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "Enter cool username"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Enter a secure password"})
    submit = SubmitField('Add User')