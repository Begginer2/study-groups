# forms.py
from flask_wtf import FlaskForm   
from flask_wtf.file import FileAllowed  # <-- ADD THIS IMPORT
# Make sure DateTimeField and DataRequired are imported
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField, SelectField,DateField,TimeField  # <-- ADD FileField & SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User



class SignUpForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CreateGroupForm(FlaskForm):
    name = StringField('Group Name', validators=[DataRequired(), Length(min=3, max=100)])
    subject = StringField('Subject', validators=[DataRequired(), Length(min=3, max=100)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    submit = SubmitField('Create Group')



# ... (at the end of the file, after CreateGroupForm)

class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# --- REPLACE YOUR OLD ResourceForm WITH THIS ---

class ResourceForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=3, max=200)])
    
    # This is the field that was missing
    description = TextAreaField('Description')
    
    resource_type = SelectField('Type', choices=[('link', 'Link'), ('file', 'File')], 
                                validators=[DataRequired()])
    
    url = StringField('URL (if link)', validators=[Length(max=500)])
    
    file = FileField('File (if file)', validators=[
        FileAllowed(['pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'doc', 'docx', 'zip'], 
                    'File type not allowed!')
    ])
    
    submit = SubmitField('Add Resource')

    # --- Add interest courses ---
class UpdateProfileForm(FlaskForm):
    interested_subjects = TextAreaField('Interested Subjects (comma-separated)',
                                       validators=[Length(max=500)])
    submit = SubmitField('Update Interests')

    # --- ADD event ,date and time---
class EventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired(), Length(min=3, max=200)])
    description = TextAreaField('Description')
    # REPLACE DateTimeField with these two:
    event_date = DateField('Event Date', format='%Y-%m-%d', validators=[DataRequired()])
    event_time = TimeField('Event Time', format='%H:%M', validators=[DataRequired()])
    submit = SubmitField('Save Event')