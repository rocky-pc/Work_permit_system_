# Industrial Work Permit Management System (IWPM) - Based on DWQHSE C-24

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from io import BytesIO
from xhtml2pdf import pisa
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iwpm.db'
app.config['SECRET_KEY'] = 'verysecretkey'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sjega82@gmail.com'  # Replace with env
app.config['MAIL_PASSWORD'] = '123456789'          # Replace with env

mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), default='receiver')  # admin, issuer, receiver, safety, gas_tester

class WorkPermit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    permit_type = db.Column(db.String(100), nullable=False)  # e.g., Hot Work, Cold Work
    location = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    gas_test_log = db.Column(db.Text)
    jsa_reference = db.Column(db.String(255))

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    permit_type = db.Column(db.String(100), unique=True)
    form_number = db.Column(db.String(50))
    color_code = db.Column(db.String(20))
    description = db.Column(db.Text)
    examples = db.Column(db.Text)
    requirements = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def dashboard():
    if current_user.role == 'admin':
        permits = WorkPermit.query.all()
    elif current_user.role == 'issuer':
        permits = WorkPermit.query.filter_by(issuer_id=current_user.id).all()
    elif current_user.role == 'receiver':
        permits = WorkPermit.query.filter_by(receiver_id=current_user.id).all()
    elif current_user.role == 'safety':
        # Show pending permits that need approval and already approved/rejected permits
        permits = WorkPermit.query.filter(
            (WorkPermit.status == 'Pending') |
            (WorkPermit.status == 'Approved') |
            (WorkPermit.status == 'Rejected')
        ).all()
    else:
        # For other roles (gas_tester or any other)
        permits = WorkPermit.query.filter(
            (WorkPermit.status == 'Approved') |
            (WorkPermit.status == 'Pending')
        ).order_by(WorkPermit.status.desc(), WorkPermit.issued_at.desc()).all()
    
    return render_template('dashboard.html', permits=permits)

@app.route('/create-admin')
def create_admin():
    # Check if admin already exists
    admin = User.query.filter_by(role='admin').first()
    if admin:
        flash('Admin already exists!', 'warning')
        return redirect(url_for('login'))
    
    # Create admin user
    admin_user = User(
        username='admin@gmail.com',
        password=generate_password_hash('admin123', method='pbkdf2:sha256'),
        role='admin'
    )
    db.session.add(admin_user)
    db.session.commit()
    flash('Admin user created successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/settings')
@login_required
def settings():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    permit_types = Settings.query.all()  # Changed from settings to Settings
    users = User.query.all()  # Added for user management
    return render_template('settings.html', permit_types=permit_types, users=users)

@app.route('/settings/initialize')
@login_required
def initialize_settings():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    permit_types = {
        'Hot Work': {
            'form': 'DRD-HSE-FOM-37',
            'color': 'PINK',
            'description': 'Hot work is any work that develops sparks, flames or heat sufficient to cause ignition.',
            'examples': 'Welding or cutting casing, welding on mud tank etc.',
            'requirements': 'Requires flame-producing tools assessment'
        },
        'Cold Work': {
            'form': 'DRD-HSE-FOM-38',
            'color': 'BLUE',
            'description': 'Cold work is work that will not produce sufficient energy to ignite flammable atmospheres/materials.',
            'examples': 'Work with hand tools, Pressure Testing, brush painting etc.',
            'requirements': 'Standard safety equipment required'
        },
        'Confined Space Entry': {
            'form': 'DRD-HSE-FOM-39',
            'color': 'GREEN',
            'description': 'Entry into any space not normally intended for human occupancy.',
            'examples': 'Mud Tank cleaning, tank inspection',
            'requirements': 'Rescue plan mandatory'
        },
        'Hazardous Release': {
            'form': 'DRD-HSE-FOM-40',
            'color': 'YELLOW',
            'description': 'Release of hazardous liquids or gases below 130°F/54°C flash point.',
            'examples': 'Transfer Diesel, opening a line, draining a vessel',
            'requirements': 'Hazard assessment mandatory'
        },
        'Electrical': {
            'form': 'DRD-HSE-FOM-41',
            'color': 'GREY',
            'description': 'Maintenance or repair of electrical equipment.',
            'examples': 'Work on high voltage electrical equipment',
            'requirements': 'LOTO procedure mandatory'
        },
        'Lifting Work': {
            'form': 'DRD-HSE-FOM-42',
            'color': 'ORANGE',
            'description': 'Mechanically-aided lifting tasks with suspended loads.',
            'examples': 'Lifting Equipment to Rig Floor, Using Web sling',
            'requirements': 'Lifting plan required'
        },
        'Third Party': {
            'form': 'DRD-HSE-FOM-43',
            'color': 'WHITE',
            'description': 'Work by third-party service providers.',
            'examples': 'Cementing operation, running casing',
            'requirements': 'Company details required'
        }
    }
    
    for type_name, details in permit_types.items():
        setting = Settings(
            permit_type=type_name,
            form_number=details['form'],
            color_code=details['color'],
            description=details['description'],
            examples=details['examples'],
            requirements=details['requirements']
        )
        db.session.add(setting)
    
    db.session.commit()
    flash('Settings initialized successfully.', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/edit/<int:setting_id>', methods=['GET', 'POST'])
@login_required
def edit_setting(setting_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    setting = Settings.query.get_or_404(setting_id)
    if request.method == 'POST':
        setting.description = request.form['description']
        setting.examples = request.form['examples']
        setting.requirements = request.form['requirements']
        db.session.commit()
        flash('Settings updated successfully.', 'success')
        return redirect(url_for('settings'))  
    return render_template('edit_settings.html', setting=setting)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/permit/new', methods=['GET', 'POST'])
@login_required
def new_permit():
    if request.method == 'POST':
        permit_type = request.form['permit_type']
        setting = Settings.query.filter_by(permit_type=permit_type).first()
        
        permit = WorkPermit(
            permit_type=permit_type,
            location=request.form['location'],
            description=request.form['description'],
            expires_at=datetime.utcnow() + timedelta(hours=12),
            issuer_id=current_user.id,
            receiver_id=request.form['receiver_id'],
            jsa_reference=request.form.get('jsa_reference')
        )
        
        if permit_type == 'Confined Space Entry':
            permit.rescue_plan = request.form.get('rescue_plan')
        elif permit_type == 'Electrical':
            permit.loto_required = True
        elif permit_type == 'Third Party':
            permit.third_party_company = request.form.get('third_party_company')
        
        permit.permit_number = f"{Settings.form_number}-{datetime.utcnow().strftime('%Y%m%d%H%M')}"
        
        db.session.add(permit)
        db.session.commit()
        flash('Permit created successfully.', 'success')
        return redirect(url_for('dashboard'))
    
    permit_types = Settings.query.all()
    receivers = User.query.filter_by(role='receiver').all()
    return render_template('new_permit.html', permit_types=permit_types, receivers=receivers)

@app.route('/permit/view/<int:permit_id>')
@login_required
def view_permit(permit_id):
    permit = WorkPermit.query.get_or_404(permit_id)
    return render_template('view_permit.html', permit=permit)

@app.route('/permit/approve/<int:permit_id>')
@login_required
def approve_permit(permit_id):
    permit = WorkPermit.query.get_or_404(permit_id)
    if current_user.role in ['admin', 'safety']:
        permit.status = 'Approved'
        db.session.commit()
        flash('Permit approved.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/permit/reject/<int:permit_id>')
@login_required
def reject_permit(permit_id):
    permit = WorkPermit.query.get_or_404(permit_id)
    if current_user.role in ['admin', 'safety']:
        permit.status = 'Rejected'
        db.session.commit()
        flash('Permit rejected.', 'warning')
    return redirect(url_for('dashboard'))

@app.route('/permit/pdf/<int:permit_id>')
@login_required
def generate_pdf(permit_id):
    permit = WorkPermit.query.get_or_404(permit_id)
    html = render_template('permit_pdf.html', permit=permit)
    result = BytesIO()
    pisa.CreatePDF(html, dest=result)
    result.seek(0)
    return send_file(result, download_name=f'permit_{permit.id}.pdf', as_attachment=True)

@app.route('/settings/user/<int:user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role in ['admin', 'issuer', 'receiver', 'safety', 'gas_tester']:
        user.role = new_role
        db.session.commit()
        flash(f'User role updated to {new_role}', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    if check_password_hash(current_user.password, current_password):
        current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Password updated successfully', 'success')
    else:
        flash('Current password is incorrect', 'danger')
    return redirect(url_for('settings'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin if not exists
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin_user = User(
                username='admin@system.com',
                password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True)
