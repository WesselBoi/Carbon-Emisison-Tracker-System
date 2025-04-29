import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_mail import Mail, Message


from itsdangerous import URLSafeTimedSerializer

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email

# Load environment variables
load_dotenv()

# App setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False





# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')   # Your Gmail address
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')   # App password (not your regular Gmail password)

mail = Mail(app)








db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Custom decorator for industry-only routes
def industry_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.user_type != 'industry':
            flash('This feature requires an industry account', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Models
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.String(20), nullable=False, default='individual')  # individual/industry
    company_name = db.Column(db.String(100))
    is_approved = db.Column(db.Boolean(), default=False)
    emissions = db.relationship('Emission', backref='owner', lazy=True)

class Emission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20), default='kg')
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    description = db.Column(db.Text, default='')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    department = db.Column(db.String(50))  # For industries
    scope = db.Column(db.String(20))  # Scope 1/2/3

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
@login_required
def index():
    # Get ONLY current user's emissions
    user_emissions = Emission.query.filter_by(user_id=current_user.id).all()
    
    if current_user.user_type == 'industry':
        return render_template('industry_dashboard.html', emissions=user_emissions)
    else:
        return render_template('individual_dashboard.html', emissions=user_emissions)






@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # For demo: just flash the link (in production, send via email)
            msg = Message(
                subject='Password Reset Request',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f'''Hi,
            
            To reset your password, click the following link:
            
            {reset_link}
            
            If you did not request this, simply ignore this email.
            
            Thanks,
            Carbon Tracker Team
            '''
            mail.send(msg)
            
        
        flash('If the email exists, a reset link has been sent.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Reset link is invalid or expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        new_password = request.form['password']
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)









@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(
            email=request.form['email'],
            password=hashed_pw,
            user_type=request.form['user_type'],
            company_name=request.form.get('company_name')
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/reports')
@login_required
def reports():
    # Industry sees only their department breakdown
    by_category = db.session.query(
        Emission.category,
        db.func.sum(Emission.amount).label('total')
    ).filter_by(user_id=current_user.id).group_by(Emission.category).all()

    by_month = db.session.query(
        db.func.strftime('%Y-%m', Emission.date).label('month'),
        db.func.sum(Emission.amount).label('total')
    ).filter_by(user_id=current_user.id).group_by('month').all()

    return render_template('reports.html', 
                         by_category=by_category,
                         by_month=by_month)




# Emission Routes
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_emission():
    if request.method == 'POST':
        emission = Emission(
            source=request.form['source'],
            category=request.form['category'],
            amount=float(request.form['amount']),
            unit=request.form['unit'],
            date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
            description=request.form.get('description', ''),
            user_id=current_user.id,
            department=request.form.get('department'),
            scope=request.form.get('scope')
        )
        db.session.add(emission)
        db.session.commit()
        flash('Record added!', 'success')
        return redirect(url_for('index'))
    
    return render_template('add_emission.html', 
                         is_industry=current_user.user_type == 'industry')



@app.route('/emissions')
@login_required
def emissions():
    user_emissions = Emission.query.filter_by(
        user_id=current_user.id
    ).order_by(Emission.date.desc()).all()
    return render_template('emissions.html', emissions=user_emissions)


@app.route('/delete/<int:id>')
@login_required
def delete_emission(id):
    emission = Emission.query.filter_by(
        id=id,
        user_id=current_user.id  # Critical security check
    ).first_or_404()  # 404 if not found or not owner
    
    db.session.delete(emission)
    db.session.commit()
    flash('Record deleted', 'success')
    return redirect(url_for('index'))

# Industry-only routes
@app.route('/bulk-upload', methods=['GET', 'POST'])
@industry_required
def bulk_upload():
    if request.method == 'POST':
        # Implement CSV processing here
        flash('Bulk upload feature coming soon!', 'info')
    return render_template('bulk_upload.html')

if __name__ == '__main__':
    app.run(debug=True)