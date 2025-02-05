from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from app import db, bcrypt
from app.models import User, FormData
from app.forms import RegistrationForm, LoginForm, SaveForm

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def register_routes(app):
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            flash('Login Unsuccessful. Please check email and password', 'danger')
        return render_template('login.html', form=form)

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        forms = FormData.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', forms=forms)

    @app.route('/save', methods=['GET', 'POST'])
    @login_required
    def save_form():
        form = SaveForm()
        if form.validate_on_submit():
            form_data = FormData(content=form.content.data, user_id=current_user.id)
            db.session.add(form_data)
            db.session.commit()
            flash('Form saved successfully!', 'success')
            return redirect(url_for('dashboard'))
        return render_template('save_form.html', form=form)