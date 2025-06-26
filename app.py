from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Capsule
from forms import LoginForm, RegisterForm, CapsuleForm
from datetime import datetime
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os

# Initialize app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///memorylane.db'
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Encryption key
KEY = b'wMk-CdQI5pFZthB0Z1wqTL1MbdJXdmdVuw7yFu2dYPQ='
fernet = Fernet(KEY)

# Flag to prevent multiple DB creations
tables_created = False

# Flag to prevent multiple DB creations
tables_created = False

@app.before_request
def create_tables():
    global tables_created
    if not tables_created:
        db.create_all()
        tables_created = True


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already taken. Please choose another.", "danger")
            return redirect(url_for('register'))

        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully!", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    capsules = Capsule.query.filter_by(user_id=current_user.id).all()
    now = datetime.now()

    # Find capsules unlocked in last 24 hours
    recently_unlocked = [
        c for c in capsules
        if c.unlock_date <= now and c.unlock_date >= now - timedelta(hours=24)
    ]

    return render_template('dashboard.html', capsules=capsules, now=now, recently_unlocked=recently_unlocked)




@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = CapsuleForm()
    if form.validate_on_submit():
        encrypted_message = fernet.encrypt(form.message.data.encode())

        file_names = []
        if form.upload.data:
            for file in form.upload.data:
                if file:
                    filename = file.filename
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    file_names.append(filename)

        unlock_datetime = datetime.combine(form.date.data, form.time.data)

        capsule = Capsule(
            title=form.title.data,
            message=encrypted_message,
            unlock_date=unlock_datetime,
            user_id=current_user.id
        )
        capsule.set_filenames(file_names)

        db.session.add(capsule)
        db.session.commit()
        flash("Capsule created successfully!")
        return redirect(url_for('dashboard'))

    return render_template('create_capsule.html', form=form)


@app.route('/capsule/<int:capsule_id>')
@login_required
def view_capsule(capsule_id):
    capsule = Capsule.query.get_or_404(capsule_id)
    if capsule.user_id != current_user.id:
        return abort(403)

    now = datetime.now()
    if capsule.unlock_date > now:
        return render_template('view_capsule.html', capsule=capsule, now=now)

    try:
        decrypted_message = fernet.decrypt(capsule.message).decode()
    except Exception:
        decrypted_message = "(Could not decrypt the message.)"

    return render_template('view_capsule.html', capsule=capsule, message=decrypted_message, now=now)

@app.route('/delete/<int:capsule_id>', methods=['POST'])
@login_required
def delete_capsule(capsule_id):
    capsule = Capsule.query.get_or_404(capsule_id)
    if capsule.user_id != current_user.id:
        abort(403)

    # Delete uploaded files
    if capsule.filenames:
        for file in capsule.filenames.split(','):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.strip())
            if os.path.exists(file_path):
                os.remove(file_path)

    db.session.delete(capsule)
    db.session.commit()
    flash("Capsule deleted successfully.")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
