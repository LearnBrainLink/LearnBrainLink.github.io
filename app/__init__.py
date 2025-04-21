import random
import string
from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from sqlalchemy.exc import SQLAlchemyError
from flask_migrate import Migrate
import logging
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# --- Added: Load environment variables from .env file ---
from dotenv import load_dotenv
load_dotenv()
# --- End Added ---


app = Flask(__name__)

# --- Configurations using os.environ.get ---
# Now these lines will correctly read variables loaded from .env
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///microvolunteering.db')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'unsafe_dev_secret_key_please_change')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure logging
# ... (logging config remains the same) ...

# Mail Configuration (reads from env vars loaded above)
# ... (mail config remains the same) ...
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ('true', '1', 't')
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', ('Unity Volunteers', app.config.get('MAIL_USERNAME', 'default@example.com'))) # Use .get for safety if username might be missing
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'dev_salt_change_me')

# Initialize extensions AFTER configuration is set
mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ... (rest of your Flask application code: token functions, models, routes, etc.) ...


# --- Token Generation/Verification ---
def generate_confirmation_token(email):
    # Use current_app proxy to access config safely
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600): # Default expiration: 1 hour
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=current_app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except Exception as e:
        app.logger.error(f"Token confirmation error: {e}") # Log error
        return False
# --- End Token Functions ---


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False) # Renamed from password_hash for consistency
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    # --- Added Field ---
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    # --- End Added Field ---

    def set_password(self, password):
        self.password = generate_password_hash(password) # Ensure this sets the 'password' field

    def check_password(self, password):
        return check_password_hash(self.password, password)

class HoursLog(db.Model):
    # ... (no changes needed here) ...
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hours = db.Column(db.Float, nullable=False)
    event = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    user = db.relationship('User', backref=db.backref('hours_logs', lazy=True))


class VolunteerOpportunity(db.Model):
    # ... (no changes needed here) ...
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(1000), nullable=False)
    creator = db.relationship('User', backref=db.backref('created_opportunities', lazy=True))


# --- Admin Code Handling ---
ADMIN_CODE = os.environ.get('ADMIN_REGISTRATION_CODE', "123456")

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register(): # Renamed from signup for consistency
    if request.method == 'POST':
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
            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'error')
                return render_template('register.html')
            if User.query.filter_by(email=email).first():
                flash('Email address already registered.', 'error')
                return render_template('register.html')

            # --- Create User (Unverified) ---
            user = User(
                username=username,
                name=name,
                age=age,
                email=email,
                is_admin=False,
                is_verified=False # Start as unverified
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit() # Commit here to get user ID if needed, though email is used for token

            # --- Send Confirmation Email ---
            try:
                token = generate_confirmation_token(user.email)
                confirm_url = url_for('confirm_email', token=token, _external=True)
                # Ensure you create templates/auth/email_confirm.html
                html = render_template('auth/email_confirm.html', confirm_url=confirm_url)
                subject = "Please confirm your email - Unity Volunteers"

                # Use default sender from config unless specified otherwise
                msg = Message(subject, recipients=[user.email], html=html)
                mail.send(msg)

                app.logger.info(f"Confirmation email sent to {user.email} for user '{user.username}'.")
                flash('Registration successful! Please check your email to activate your account.', 'success')
                return redirect(url_for('login'))

            except Exception as e:
                db.session.rollback() # Rollback user creation if email fails
                app.logger.error(f"Error sending confirmation email for {email}: {e}")
                flash('Registration failed due to an error sending confirmation email. Please contact support.', 'error')
                return render_template('register.html')

        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error during registration: {e}")
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html')
    # GET request
    return render_template('register.html')


# --- Added Route ---
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token) # Verify the token, returns email or False
        if not email:
            flash('The confirmation link is invalid or has expired.', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if not user:
            app.logger.warning(f"Confirmation attempt failed: No user found for email derived from token ({email}).")
            flash('User not found for this confirmation link.', 'error')
            return redirect(url_for('login'))

        if user.is_verified:
            flash('Account already confirmed. Please login.', 'success')
        else:
            user.is_verified = True
            # db.session.add(user) # Not needed if user object is tracked by session
            db.session.commit()
            app.logger.info(f"Account confirmed successfully for user '{user.username}' (Email: {email}).")
            flash('You have confirmed your account. Thanks! You can now log in.', 'success')
        return redirect(url_for('login')) # Redirect to login after confirmation attempt

    except SQLAlchemyError as e:
         db.session.rollback()
         app.logger.error(f"Database error during email confirmation processing for token {token}: {e}")
         flash('An error occurred during confirmation. Please try again or contact support.', 'error')
         return redirect(url_for('login'))
    except Exception as e: # Catch other potential errors
        app.logger.error(f"Unexpected error during email confirmation processing for token {token}: {e}")
        flash('An unexpected error occurred. Please try again or contact support.', 'error')
        return redirect(url_for('login'))
# --- End Added Route ---


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username') # Assuming login via username
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        try:
            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                # --- Added Verification Check ---
                if not user.is_verified:
                    flash('Your account has not been verified. Please check your email for the confirmation link.', 'warning')
                    app.logger.warning(f"Login attempt failed for unverified user '{username}'.")
                    return render_template('login.html') # Show login page again
                # --- End Verification Check ---

                session['user_id'] = user.id
                session['is_admin'] = user.is_admin
                app.logger.info(f"Login successful for verified user '{username}'. Setting session is_admin to {user.is_admin}")
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                app.logger.warning(f"Failed login attempt for username '{username}'.")
                return render_template('login.html')
        except SQLAlchemyError as e:
            app.logger.error(f"Database error during login for user '{username}': {e}")
            flash('An error occurred during login. Please try again.', 'error')
            return render_template('login.html')
    # GET request
    return render_template('login.html')


# --- Other routes (dashboard, logout, account, admin_register, etc.) ---
# ... (Keep your existing routes for dashboard, logout, account, etc.) ...
# Ensure routes requiring login check session['user_id']
# Ensure sensitive actions check user.is_admin from the DB object where necessary

@app.route('/volunteer-opportunities', methods=['GET', 'POST'])
def volunteeropportunities():
    if 'user_id' not in session:
        flash('Please log in to view or create volunteer opportunities.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found. Please log in again.', 'error')
        session.pop('user_id', None)
        session.pop('is_admin', None)
        return redirect(url_for('login'))

    # --- Check Verification Status ---
    if not user.is_verified:
         flash('Please verify your email address to access this page.', 'warning')
         return redirect(url_for('dashboard')) # Or wherever you want unverified users to go
    # --- End Verification Check ---

    opportunities = VolunteerOpportunity.query.order_by(VolunteerOpportunity.date.desc()).all()

    if request.method == 'POST':
        if not user.is_admin: # Check admin status from DB for POST
            app.logger.warning(f"Unauthorized POST attempt to add opportunity by user '{user.username}' (ID: {user_id}).")
            flash('You do not have permission to add opportunities.', 'warning')
            return redirect(url_for('volunteeropportunities'))

        # ... (rest of your POST handling for creating opportunities) ...
        event = request.form.get('event')
        date_str = request.form.get('date')
        duration_str = request.form.get('duration')
        location = request.form.get('location')
        link = request.form.get('link')

        if not all([event, date_str, duration_str, location, link]):
            flash('All fields are required to create an opportunity.', 'error')
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
            return redirect(url_for('volunteeropportunities'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error creating opportunity: {e}")
            flash('An error occurred creating the opportunity. Please try again.', 'error')
            return render_template('volunteeropportunities.html', opportunities=opportunities, is_admin=user.is_admin)

    # GET request or POST validation failure
    return render_template('volunteeropportunities.html', opportunities=opportunities, is_admin=user.is_admin) # Pass admin status


@app.route('/volunteer-hours', methods=['GET', 'POST'])
def volunteerhours():
    if 'user_id' not in session:
        flash('Please log in to log your volunteer hours.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found. Please log in again.', 'error')
        session.pop('user_id', None)
        session.pop('is_admin', None)
        return redirect(url_for('login'))

    # --- Check Verification Status ---
    if not user.is_verified:
         flash('Please verify your email address to access this page.', 'warning')
         return redirect(url_for('dashboard'))
    # --- End Verification Check ---

    logs = HoursLog.query.filter_by(user_id=user_id).order_by(HoursLog.date.desc()).all()
    total_hours = sum(log.hours for log in logs)

    if request.method == 'POST':
        # ... (rest of your POST handling for logging hours) ...
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
            if date.date() > datetime.now().date():
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
            return redirect(url_for('volunteerhours'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error logging hours: {e}")
            flash('An error occurred logging hours. Please try again.', 'error')
            return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin)

    # GET request or POST validation failure
    return render_template('volunteerhours.html', logs=logs, total_hours=total_hours, is_admin=user.is_admin) # Pass admin status


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    try:
        user = db.session.get(User, user_id)
        if not user:
            session.pop('user_id', None)
            session.pop('is_admin', None)
            flash('User not found. Please log in again.', 'error')
            return redirect(url_for('login'))

        # --- Check Verification Status (Optional but good practice) ---
        if not user.is_verified:
             flash('Please verify your email address using the link sent to you.', 'warning')
             # Decide where to redirect or show a limited dashboard
             # return render_template('dashboard_unverified.html', name=user.name, is_admin=user.is_admin)

        logs = HoursLog.query.filter_by(user_id=user_id).all()
        total_hours = sum(log.hours for log in logs)
        is_admin_status = user.is_admin
        app.logger.info(f"Dashboard access for user '{user.username}'. Verified: {user.is_verified}, Admin status: {is_admin_status}")
        return render_template('dashboard.html', name=user.name, total_hours=total_hours, is_admin=is_admin_status)
    except SQLAlchemyError as e:
        app.logger.error(f"Database error on dashboard for user {user_id}: {e}")
        flash('An error occurred accessing the dashboard.', 'error')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    # ... (Keep existing logout code) ...
    user_id = session.get('user_id')
    username = 'Unknown user'
    if user_id:
        user = db.session.get(User, user_id)
        if user:
            username = user.username
    app.logger.info(f"User '{username}' (ID: {user_id}) logged out.")
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
    user = db.session.get(User, user_id)

    if not user:
        # ... (Keep existing user not found handling) ...
        session.pop('user_id', None)
        session.pop('is_admin', None)
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    # --- Check Verification Status ---
    if not user.is_verified:
         flash('Please verify your email address to access this page.', 'warning')
         return redirect(url_for('dashboard'))
    # --- End Verification Check ---

    is_admin_status = user.is_admin

    if request.method == 'POST':
        # ... (Keep existing POST logic for updating account) ...
        # NOTE: If email is updated, you SHOULD re-verify the NEW email.
        # This adds complexity: Set is_verified=False, send new link.
        # For simplicity, this example doesn't re-verify on email change.
        original_email = user.email
        new_email = request.form.get('email_input')
        name_input = request.form.get('name_input')
        age_input_str = request.form.get('age_input')

        if not all([name_input, new_email, age_input_str]):
            flash('Name, email, and age are required.', 'error')
            return render_template('account.html', name=user.name, email=user.email, age=user.age, is_admin=is_admin_status)

        try:
            age_input = int(age_input_str)
            if age_input <= 0:
                flash('Age must be a positive number.', 'error')
                return render_template('account.html', name=user.name, email=user.email, age=user.age, is_admin=is_admin_status)
        except ValueError:
            flash('Invalid age format. Please enter a number.', 'error')
            return render_template('account.html', name=user.name, email=user.email, age=user.age, is_admin=is_admin_status)

        email_changed = new_email != original_email
        if email_changed and User.query.filter(User.id != user_id, User.email == new_email).first():
            flash('That email address is already registered by another user.', 'error')
            return render_template('account.html', name=name_input, email=original_email, age=age_input_str, is_admin=is_admin_status)

        user.name = name_input
        user.email = new_email
        user.age = age_input

        try:
            db.session.commit()
            flash('Account updated successfully!', 'success')
            app.logger.info(f"Account updated for user '{user.username}' (ID: {user_id})")
            # Re-render with updated user data
            return render_template('account.html', name=user.name, email=user.email, age=user.age, is_admin=is_admin_status)
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error updating account for user {user_id}: {e}")
            flash('An error occurred updating the account. Please try again.', 'error')
            # Re-fetch original data on error
            user = db.session.get(User, user_id) # Re-fetch
            is_admin_status = user.is_admin if user else False
            return render_template('account.html', name=user.name if user else '', email=user.email if user else '', age=user.age if user else '', is_admin=is_admin_status)

    # GET request
    return render_template('account.html', name=user.name, email=user.email, age=user.age, is_admin=is_admin_status)


@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        # ... (Keep existing admin registration logic) ...
        # IMPORTANT: Admin accounts created here are NOT automatically verified
        # by email in this flow. You might want to add verification or handle separately.
        username = request.form.get('username')
        name = request.form.get('name')
        age_str = request.form.get('age')
        email = request.form.get('email')
        password = request.form.get('password')
        confirmPassword = request.form.get('confirmPassword')
        admin_code = request.form.get('adminCode')

        # ... (rest of your validation) ...
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

        if admin_code != ADMIN_CODE:
            flash('Invalid admin code', 'error')
            return render_template('admin_register.html')

        try:
            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'error')
                return render_template('admin_register.html')
            if User.query.filter_by(email=email).first():
                flash('Email address already registered.', 'error')
                return render_template('admin_register.html')

            # Create user with is_admin=True, is_verified=True (assuming admin code implies verification)
            # OR set is_verified=False and require email confirmation for admins too.
            user = User(username=username, name=name, age=age, email=email, is_admin=True, is_verified=True) # Set verified for admin
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            app.logger.info(f"Admin account created successfully for user '{username}'.")
            flash('Admin account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error during admin registration: {e}")
            flash('An error occurred during admin registration. Please try again.', 'error')
            return render_template('admin_register.html')

    # GET request
    return render_template('admin_register.html')


# This route seems redundant if you just link to /admin/register
# @app.route('/admin/register-page')
# def show_admin_register_form():
#     return render_template('admin_register.html')


if __name__ == '__main__':
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    # Create tables if they don't exist when running directly (for dev)
    # Consider removing this if using migrations exclusively
    # with app.app_context():
    #     db.create_all()
    app.run(debug=is_debug)