import random
import string
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from sqlalchemy.exc import SQLAlchemyError
from flask_migrate import Migrate
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///microvolunteering.db')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'unsafe_dev_secret_key_please_change')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To suppress a warning

# Configure logging (very important!)
logging.basicConfig(level=logging.INFO)  # Or logging.DEBUG, etc.
app.logger.setLevel(logging.INFO)

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Migrate with app and db


# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class HoursLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hours = db.Column(db.Float, nullable=False)
    event = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False)

    # Define relationship
    user = db.relationship('User', backref=db.backref('hours_logs', lazy=True))


class VolunteerOpportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(1000), nullable=False)

    # Define relationship
    creator = db.relationship('User', backref=db.backref('created_opportunities', lazy=True))


# --- Admin Code Handling ---
# Use environment variable or default (unsafe for production)
ADMIN_CODE = os.environ.get('ADMIN_REGISTRATION_CODE', "123456")


# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Use .get() for safer access
        username = request.form.get('username')
        name = request.form.get('name')
        age_str = request.form.get('age')
        email = request.form.get('email')
        password = request.form.get('password')
        confirmPassword = request.form.get('confirmPassword')

        if not all([username, name, age_str, email, password, confirmPassword]):
            flash('All fields are required.', 'error')
            return render_template('register.html')

        try:
            age = int(age_str)
            if age <= 0:
                flash('Age must be a positive number.', 'error')
                return render_template('register.html')
        except ValueError:
            flash('Invalid age format. Please enter a number.', 'error')
            return render_template('register.html')

        if password != confirmPassword:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        try:
            # Check if username or email already exists
            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'error')
                return render_template('register.html')
            if User.query.filter_by(email=email).first():
                flash('Email address already registered.', 'error')
                return render_template('register.html')

            # Create user with is_admin=False by default
            user = User(username=username, name=name, age=age, email=email, is_admin=False)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error during registration: {e}")  # Example logging
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html')
    # GET request
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        try:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                session['user_id'] = user.id
                session['is_admin'] = user.is_admin  # Store admin status in session
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                return render_template('login.html')
        except SQLAlchemyError as e:
            app.logger.error(f"Database error during login: {e}")  # Example logging
            flash('An error occurred during login. Please try again.', 'error')
            return render_template('login.html')
    # GET request
    return render_template('login.html')


@app.route('/volunteer-opportunities', methods=['GET', 'POST'])
def volunteeropportunities():
    if 'user_id' not in session:
        flash('Please log in to view or create volunteer opportunities.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    # Fetch opportunities initially for GET request or if POST fails before redirect
    opportunities = VolunteerOpportunity.query.order_by(VolunteerOpportunity.date.desc()).all()

    if request.method == 'POST':
        if not session.get('is_admin', False):  # Check admin status
            flash('You do not have permission to add opportunities.', 'warning')
            return redirect(url_for('volunteeropportunities'))

        event = request.form.get('event')
        date_str = request.form.get('date')
        duration_str = request.form.get('duration')
        location = request.form.get('location')
        link = request.form.get('link')

        if not all([event, date_str, duration_str, location, link]):
            flash('All fields are required to create an opportunity.', 'error')
            # Render again with fetched opportunities
            return render_template('volunteeropportunities.html', opportunities=opportunities, is_admin=user.is_admin)

        try:
            duration = float(duration_str)
            if duration <= 0:
                flash('Duration must be a positive number.', 'error')
                return render_template('volunteeropportunities.html', opportunities=opportunities, is_admin=user.is_admin)
        except ValueError:
            flash('Invalid duration format. Please enter a number.', 'error')
            return render_template('volunteeropportunities.html', opportunities=opportunities, is_admin=user.is_admin)

        try:
            date = datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            flash('Invalid date format. Please use %Y-%m-%d.', 'error')
            return render_template('volunteeropportunities.html', opportunities=opportunities, is_admin=user.is_admin)

        try:
            opportunity = VolunteerOpportunity(
                creator_id=user_id, event=event, date=date, duration=duration, location=location, link=link)
            db.session.add(opportunity)
            db.session.commit()
            flash('Opportunity created successfully!', 'success')
            return redirect(url_for('volunteeropportunities'))  # Redirect after successful POST
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error creating opportunity: {e}")  # Example logging
            flash('An error occurred creating the opportunity. Please try again.', 'error')
            # No need to fetch opportunities again, already fetched before 'if POST'
            return render_template('volunteeropportunities.html', opportunities=opportunities, is_admin=user.is_admin)

    # GET request - Render with fetched opportunities
    return render_template('volunteeropportunities.html', opportunities=opportunities, is_admin=user.is_admin)


@app.route('/volunteer-hours', methods=['GET', 'POST'])
def volunteerhours():
    if 'user_id' not in session:
        flash('Please log in to log your volunteer hours.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    # Fetch logs initially for GET or if POST fails before redirect
    logs = HoursLog.query.filter_by(user_id=user_id).order_by(HoursLog.date.desc()).all()
    total_hours = sum(log.hours for log in logs)  # More concise sum

    if request.method == 'POST':
        hours_str = request.form.get('hours')
        event = request.form.get('event')
        date_str = request.form.get('date')

        if not all([hours_str, event, date_str]):
            flash('All fields are required to log hours.', 'error')
            return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin)

        try:
            hours = float(hours_str)
            if hours <= 0:
                flash('Hours must be a positive number.', 'error')
                return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin)
        except ValueError:
            flash('Invalid hours format. Please enter a number.', 'error')
            return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin)

        try:
            date = datetime.strptime(date_str, "%Y-%m-%d")
            if date > datetime.now():
                flash('Cannot log hours for a future date.', 'error')
                return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin)
        except ValueError:
            flash('Invalid date format. Please use %Y-%m-%d.', 'error')
            return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin)

        try:
            log = HoursLog(user_id=user_id, hours=hours, event=event, date=date)
            db.session.add(log)
            db.session.commit()
            flash('Hours logged successfully!', 'success')
            return redirect(url_for('volunteerhours'))  # Redirect after successful POST
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error logging hours: {e}")  # Example logging
            flash('An error occurred logging hours. Please try again.', 'error')
            # No need to fetch logs/total again
            return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin)

    # GET request - Render with fetched logs/total
    return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']  # Get user_id once

    try:
        # Use get_or_404 for cleaner handling of not found user
        user = db.session.get(User, user_id)  # Use newer session.get method
        if not user:
            # This case might be less likely now with session.get behavior but keep check
            session.pop('user_id', None)
            session.pop('is_admin', None)
            flash('User not found. Please log in again.', 'error')
            return redirect(url_for('login'))

        logs = HoursLog.query.filter_by(user_id=user_id).all()
        total_hours = sum(log.hours for log in logs)
        is_admin = session.get('is_admin', False)
        return render_template('dashboard.html', name=user.name, total_hours=total_hours, is_admin=is_admin)
    except SQLAlchemyError as e:
        app.logger.error(f"Database error on dashboard for user {user_id}: {e}")  # Example logging
        flash('An error occurred accessing the dashboard.', 'error')
        return redirect(url_for('login'))  # Redirect on error


@app.route('/logout')
def logout():
    # Remove user info from session
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'user_id' not in session:
        flash('Please log in to manage your account.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    # Use session.get for user object - handles potential DB errors better within try block
    user = db.session.get(User, user_id)

    if not user:
        session.pop('user_id', None)
        session.pop('is_admin', None)
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        original_email = user.email
        new_email = request.form.get('email_input')
        name_input = request.form.get('name_input')
        age_input_str = request.form.get('age_input')

        if not all([name_input, new_email, age_input_str]):
            flash('Name, email, and age are required.', 'error')
            return render_template('account.html', name=user.name, email=user.email, age=user.age)

        try:
            age_input = int(age_input_str)
            if age_input <= 0:
                flash('Age must be a positive number.', 'error')
                return render_template('account.html', name=user.name, email=user.email, age=user.age)
        except ValueError:
            flash('Invalid age format. Please enter a number.', 'error')
            return render_template('account.html', name=user.name, email=user.email, age=user.age)

        # Check email uniqueness only if it changed
        email_changed = new_email != original_email
        if email_changed and User.query.filter(User.id != user_id, User.email == new_email).first():
            flash('That email address is already registered by another user.', 'error')
            # Render with originally fetched user data but keep attempted name/age changes in form
            return render_template('account.html', name=name_input, email=original_email, age=age_input_str)

        # Update user object
        user.name = name_input
        user.email = new_email
        user.age = age_input

        try:
            db.session.commit()
            flash('Account updated successfully!', 'success')
            # Render template directly to show updated info without full redirect
            return render_template('account.html', name=user.name, email=user.email, age=user.age)
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error updating account for user {user_id}: {e}")  # Example logging
            flash('An error occurred updating the account. Please try again.', 'error')
            # Re-fetch original data before rendering on error
            user = db.session.get(User, user_id)  # Use session.get again
            return render_template('account.html', name=user.name, email=user.email, age=user.age)

    # GET request - Render with user data fetched at the start
    return render_template('account.html', name=user.name, email=user.email, age=user.age)


@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form.get('username')
        name = request.form.get('name')
        age_str = request.form.get('age')
        email = request.form.get('email')
        password = request.form.get('password')
        confirmPassword = request.form.get('confirmPassword')
        admin_code = request.form.get('adminCode')

        if not all([username, name, age_str, email, password, confirmPassword, admin_code]):
            flash('All fields are required.', 'error')
            return render_template('admin_register.html')

        try:
            age = int(age_str)
            if age <= 0:
                flash('Age must be a positive number.', 'error')
                return render_template('admin_register.html')
        except ValueError:
            flash('Invalid age format. Please enter a number.', 'error')
            return render_template('admin_register.html')

        if password != confirmPassword:
            flash('Passwords do not match', 'error')
            return render_template('admin_register.html')

        # Verify Admin Code
        if admin_code != ADMIN_CODE:
            flash('Invalid admin code', 'error')
            return render_template('admin_register.html')

        try:
            # Check if username or email already exists
            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'error')
                return render_template('admin_register.html')
            if User.query.filter_by(email=email).first():
                flash('Email address already registered.', 'error')
                return render_template('admin_register.html')

            user = User(username=username, name=name, age=age, email=email, is_admin=True)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Admin account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()  # Uncommented rollback
            app.logger.error(f"Database error during admin registration: {e}")  # Example logging
            # Removed the explicit print statements from previous debug step
            flash('An error occurred during admin registration. Please try again.', 'error')
            return render_template('admin_register.html')

    # GET request
    return render_template('admin_register.html')


@app.route('/admin/register-page')
def show_admin_register_form():
    return render_template('admin_register.html')


# Optional admin decorator remains commented out

if __name__ == '__main__':
    # Set debug based on environment variable for better practice
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    app.run(debug=is_debug)