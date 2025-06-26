from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, TimeField, MultipleFileField
from flask_wtf.file import FileAllowed
from wtforms.validators import DataRequired, Length
from datetime import datetime

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class CapsuleForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=150)])
    message = TextAreaField("Message to Future You", validators=[DataRequired()])
    
    upload = MultipleFileField(
        "Attach files",
        validators=[
            FileAllowed(['txt', 'mp3', 'mp4', 'png', 'jpg', 'jpeg', 'pdf'],
                        'Allowed types: txt, mp3, mp4, png, jpg, jpeg, pdf')
        ]
    )
    
    date = DateField("Unlock Date", format='%Y-%m-%d', validators=[DataRequired()])
    time = TimeField("Unlock Time", format='%H:%M', validators=[DataRequired()])
    submit = SubmitField("Save Capsule")

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators=extra_validators):
            return False

        unlock_datetime = datetime.combine(self.date.data, self.time.data)
        if unlock_datetime <= datetime.now():
            self.date.errors.append("Unlock date & time must be in the future.")
            return False

        return True
