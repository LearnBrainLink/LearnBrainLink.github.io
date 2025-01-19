from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
# Use SQLite for simplicity
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///microvolunteering.db'
app.secret_key = 'CHANGE_KEY_IN_PRODUCTION'
db = SQLAlchemy(app)

# Define database models


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

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


class VolunteerOpportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    event = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(1000), nullable=False)


# Create database tables
with app.app_context():
    db.create_all()

# Routes


@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        age = request.form['age']
        email = request.form['email']
        password = request.form['password']
        confirmPassword = request.form['confirmPassword']

        if password != confirmPassword:
            flash('Passwords do not match')
            return render_template('register.html')

        user = User(username=username, name=name, age=age, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id  # Store user ID in the session
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return render_template('login.html')
    return render_template('login.html')


@app.route('/volunteer-opportunities', methods=['GET', 'POST'])
def volunteeropportunites():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    if request.method == 'POST':
        event = request.form['event']
        date = datetime.strptime(request.form['date'], "%Y-%m-%d")
        duration = request.form['duration']
        location = request.form['location']
        link = request.form['link']
        opportunity = VolunteerOpportunity(
            creator_id=user_id, event=event, date=date, duration=duration, location=location, link=link)
        db.session.add(opportunity)
        db.session.commit()
        flash('Opportunity created successfully!')
        return redirect(url_for('volunteeropportunites'))
    return render_template('volunteeropportunities.html', opportunities=VolunteerOpportunity.query.all())


@app.route('/volunteer-hours', methods=['GET', 'POST'])
def volunteerhours():
    if request.method == 'POST':
        hours = request.form['hours']
        event = request.form['event']
        date = datetime.strptime(request.form['date'], "%Y-%m-%d")
        log = HoursLog(user_id=session['user_id'],
                       hours=hours, event=event, date=date)
        db.session.add(log)
        db.session.commit()
        flash('Hours logged successfully!')
        return redirect(url_for('volunteerhours'))
    if 'user_id' in session:
        logs = HoursLog.query.filter_by(user_id=session['user_id']).all()
        return render_template('volunteerhours.html', logs=logs, total_hours=sum([log.hours for log in logs]))
    else:
        return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        logs = HoursLog.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', name=user.name, total_hours=sum([log.hours for log in logs]))
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    if 'user_id' in session:
        session.pop('user_id')  # Remove the user ID from the session
        flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if request.method == 'POST':
            user.name = request.form['name_input']
            user.email = request.form['email_input']
            user.age = request.form['age_input']
            db.session.commit()
            flash('Account updated successfully!')
            return redirect(url_for('account'))
        return render_template('account.html', name=user.name, email=user.email, age=user.age)
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
