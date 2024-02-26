from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

class SignUpForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class MessageForm(FlaskForm):
    recipient_name = StringField('Recipient', render_kw={'readonly': True})
    recipient_id = HiddenField('Recipient ID')
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')
