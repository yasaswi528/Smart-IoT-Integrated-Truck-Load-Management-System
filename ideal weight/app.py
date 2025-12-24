from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail, Message
import os
import random
import string
import requests
from datetime import datetime
import json
from itsdangerous import URLSafeTimedSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer
import joblib
import numpy as np

# Load the trained model
model = joblib.load("ideal_weight_xgb_model.pkl")

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'purpletech098@gmail.com'
app.config['MAIL_PASSWORD'] = 'lvug jwcb alcr jvan'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['THINGSPEAK_API_KEY'] = 'N0C3ZJ2O6IWWTD33'
app.config['THINGSPEAK_CHANNEL_ID'] = '3111897'  # Default channel ID

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    admin_code = db.Column(db.String(10), unique=True, nullable=False)
    profile_image = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship('User', backref='manager', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'admin_id': self.id}, salt='admin-reset')
    
    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            admin_id = s.loads(token, salt='admin-reset', max_age=1800)['admin_id']
        except:
            return None
        return Admin.query.get(admin_id)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    manager_id = db.Column(db.String(10), db.ForeignKey('admin.admin_code'), nullable=False)
    profile_image = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    calculations = db.relationship('Calculation', backref='author', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt='user-reset')
    
    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt='user-reset', max_age=1800)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Calculation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    weight = db.Column(db.Float, nullable=False)
    pressure = db.Column(db.Float, nullable=False)
    ideal_weight = db.Column(db.Float, nullable=False)
    temperature = db.Column(db.Float, nullable=False)
    result = db.Column(db.Float, nullable=False)
    formula = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Login Manager Setup
@login_manager.user_loader
def load_user(user_id):
    if session.get('is_admin'):
        return Admin.query.get(int(user_id))
    return User.query.get(int(user_id))

# Utility Functions
def generate_admin_code():
    return ''.join(random.choices(string.digits, k=10))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def send_reset_email(user, is_admin=False):
    try:
        token = user.get_reset_token()
        reset_url = url_for('reset_password', token=token, _external=True)
        
        msg = Message('Password Reset Request',
                     sender=app.config['MAIL_USERNAME'],
                     recipients=[user.email])
        msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.
'''
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")
        # Print reset link to console as fallback
        print(f"Password reset link: {reset_url}")
        return False

def get_thingspeak_data(channel_id=None):
    channel = channel_id or app.config['THINGSPEAK_CHANNEL_ID']
    url = f"https://api.thingspeak.com/channels/{channel}/feeds.json?results=3"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        feeds = data.get('feeds', [])
        if feeds:
            latest = feeds[-1]
            # Get last 3 fields with values
            values = [v for k, v in latest.items() if k.startswith('field') and v is not None][-3:]
            return values
    return [0, 0, 0]  # Default values if fetch fails

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_type = request.form.get('user_type')
        
        if user_type == 'admin':
            admin = Admin.query.filter_by(username=username).first()
            if admin and check_password_hash(admin.password_hash, password):
                login_user(admin)
                session['is_admin'] = True
                flash('Logged in successfully as Admin!', 'success')
                return redirect(url_for('admin_dashboard'))
        else:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                session['is_admin'] = False
                flash('Logged in successfully!', 'success')
                return redirect(url_for('user_dashboard'))
        
        flash('Login unsuccessful. Please check username, password, and user type', 'danger')
    
    return render_template('login.html')

@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
        elif Admin.query.filter_by(username=username).first():
            flash('Username already taken!', 'danger')
        elif Admin.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
        else:
            admin_code = generate_admin_code()
            hashed_password = generate_password_hash(password)
            admin = Admin(
                username=username,
                email=email,
                phone=phone,
                password_hash=hashed_password,
                admin_code=admin_code
            )
            db.session.add(admin)
            db.session.commit()
            flash(f'Admin account created successfully! Your Admin ID is: {admin_code}', 'success')
            return redirect(url_for('login'))
    
    return render_template('register_admin.html')

@app.route('/register/user', methods=['GET', 'POST'])
def register_user():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        manager_id = request.form.get('manager_id')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken!', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
        elif not Admin.query.filter_by(admin_code=manager_id).first():
            flash('Invalid Manager ID!', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            user = User(
                username=username,
                email=email,
                phone=phone,
                password_hash=hashed_password,
                manager_id=manager_id
            )
            db.session.add(user)
            db.session.commit()
            flash('User account created successfully!', 'success')
            return redirect(url_for('login'))
    
    return render_template('register_user.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('user_dashboard'))
    
    users = User.query.filter_by(manager_id=current_user.admin_code).all()
    total_users = len(users)
    
    # Get calculation stats
    today = datetime.utcnow().date()
    calculations_today = Calculation.query.join(User).filter(
        User.manager_id == current_user.admin_code,
        db.func.date(Calculation.timestamp) == today
    ).count()
    
    total_calculations = Calculation.query.join(User).filter(
        User.manager_id == current_user.admin_code
    ).count()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         calculations_today=calculations_today,
                         total_calculations=total_calculations,
                         users=users)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    # Get Thingspeak data
    thingspeak_values = get_thingspeak_data()
    
    # Get calculation stats
    today = datetime.utcnow().date()
    calculations_today = Calculation.query.filter_by(
        user_id=current_user.id
    ).filter(
        db.func.date(Calculation.timestamp) == today
    ).count()
    
    total_calculations = Calculation.query.filter_by(
        user_id=current_user.id
    ).count()
    
    return render_template('user_dashboard.html',
                         thingspeak_values=thingspeak_values,
                         calculations_today=calculations_today,
                         total_calculations=total_calculations)

@app.route('/calculate', methods=['GET', 'POST'])
@login_required
def calculate():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    # Get current ThingSpeak values
    thingspeak_values = get_thingspeak_data()
    
    if request.method == 'POST':
        try:
            weight = float(request.form.get('weight'))
            pressure = float(request.form.get('pressure'))
            ideal_weight = float(request.form.get('ideal_weight'))
            temperature = float(request.form.get('temperature'))
            ###########

            # Predict ideal weight using the trained model
            features = np.array([[10000, temperature, pressure, weight, ideal_weight]])
            result = float(model.predict(features)[0])

            # Your calculation formula
            #result = (10000-(weight*0.1)-(abs(pressure-35)*0.2)-(abs(ideal_weight-50)*0.3))
            result = round(result, 2)

            ###########
            calculation = Calculation(
                weight=weight,
                pressure=pressure,
                ideal_weight=ideal_weight,
                temperature=temperature,
                result=result,
                formula="Predicted using Xgboost model",
                user_id=current_user.id
            )
            db.session.add(calculation)
            db.session.commit()
            
            flash(f'Calculation complete! Result: {result}', 'success')
            return redirect(url_for('history'))
        except ValueError:
            flash('Please enter valid numbers for all fields', 'danger')
    
    return render_template('calculate.html', thingspeak_values=thingspeak_values)

@app.route('/history')
@login_required
def history():
    if session.get('is_admin'):
        # Admin view - show all users' calculations
        calculations = Calculation.query.join(User).filter(
            User.manager_id == current_user.admin_code
        ).order_by(Calculation.timestamp.desc()).all()
    else:
        # User view - show only their calculations
        calculations = Calculation.query.filter_by(
            user_id=current_user.id
        ).order_by(Calculation.timestamp.desc()).all()
    
    today = datetime.utcnow().date()
    calculations_today = len([c for c in calculations if c.timestamp.date() == today])
    total_calculations = len(calculations)
    
    return render_template('history.html',
                         calculations=calculations,
                         calculations_today=calculations_today,
                         total_calculations=total_calculations)

@app.route('/graphs')
@login_required
def graphs():
    # Get Thingspeak data
    thingspeak_values = get_thingspeak_data()
    
    # Prepare data for Chart.js
    labels = ["Value 1", "Value 2", "Value 3"]
    data = {
        'labels': labels,
        'values': thingspeak_values,
        'colors': ['#4e73df', '#1cc88a', '#36b9cc']
    }
    
    return render_template('graphs.html', chart_data=data)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.username = request.form.get('username')
        current_user.email = request.form.get('email')
        current_user.phone = request.form.get('phone')
        
        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.profile_image = filename
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user_type = request.form.get('user_type')
        
        if user_type == 'admin':
            user = Admin.query.filter_by(email=email).first()
        else:
            user = User.query.filter_by(email=email).first()
        
        if user:
            email_sent = send_reset_email(user, user_type == 'admin')
            if email_sent:
                flash('An email has been sent with instructions to reset your password.', 'info')
            else:
                flash('Password reset link generated but could not send email. Check console for the link.', 'warning')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email.', 'danger')
    
    return render_template('forgot_password.html')
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    # Try admin first
    user = Admin.verify_reset_token(token)
    if not user:
        # Try user if admin token invalid
        user = User.verify_reset_token(token)
    
    if not user:
        flash('That is an invalid or expired token', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
        else:
            user.password_hash = generate_password_hash(password)
            db.session.commit()
            flash('Your password has been updated! You can now log in', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)
# API Endpoints
@app.route('/api/thingspeak')
@login_required
def thingspeak_api():
    data = get_thingspeak_data()
    return jsonify({
        'values': data,
        'labels': ['Value 1', 'Value 2', 'Value 3'],
        'colors': ['#4e73df', '#1cc88a', '#36b9cc']
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
