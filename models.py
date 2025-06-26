from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

class Capsule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.LargeBinary, nullable=False)
    filenames = db.Column(db.Text, nullable=True)  # stores JSON list of filenames
    unlock_date = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def set_filenames(self, file_list):
        self.filenames = json.dumps(file_list)

    def get_filenames(self):
        if self.filenames:
            return json.loads(self.filenames)
        return []
