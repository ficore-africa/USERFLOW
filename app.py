import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel, get_locale
from flask_compress import Compress
from flask_cors import CORS
from flask_session import Session
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from werkzeug.security import check_password_hash
import uuid
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import models and utilities
from models import create_user, get_user_by_email, get_user, get_financial_health, get_budgets, get_bills, get_net_worth, get_emergency_funds, get_learning_progress, get_quiz_results, to_dict_financial_health, to_dict_budget, to_dict_bill, to_dict_net_worth, to_dict_emergency_fund, to_dict_learning_progress, to_dict_quiz_result, initialize_database
from translations import trans
from session_utils import create_anonymous_session
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, is_valid_email, get_mongo_db, is_admin, get_mail, get_limiter, mongo_client, login_manager, flask_session, csrf, babel, compress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/ficodb')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'ficore:'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# Babel configuration
app.config['LANGUAGES'] = {
    'en': 'English',
    'ha': 'Hausa'
}
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_DEFAULT_TIMEZONE'] = 'UTC'

# Initialize MongoDB
try:
    global mongo_client
    mongo_client = MongoClient(app.config['MONGO_URI'])
    app.config['MONGO_CLIENT'] = mongo_client
    db = mongo_client.ficodb
    
    # Test connection
    mongo_client.admin.command('ping')
    logger.info("MongoDB connection established successfully")
    
    # Initialize database schema
    initialize_database(app)
    
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    logger.error(f"Failed to connect to MongoDB: {str(e)}")
    raise RuntimeError("MongoDB connection failed")

# Initialize extensions
csrf.init_app(app)
babel.init_app(app)
compress.init_app(app)
flask_session.init_app(app)
CORS(app)

# Configure login manager
login_manager.init_app(app)
login_manager.login_view = 'users_blueprint.login'
login_manager.login_message = trans('general_login_required', default='Please log in to access this page.')
login_manager.login_message_category = 'info'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email, display_name=None, role='personal', username=None, is_admin=False, setup_complete=False, coin_balance=0, language='en', dark_mode=False):
        self.id = id
        self.email = email
        self.username = username or display_name or email.split('@')[0]
        self.role = role
        self.display_name = display_name or self.username
        self.is_admin = is_admin
        self.setup_complete = setup_complete
        self.coin_balance = coin_balance
        self.language = language
        self.dark_mode = dark_mode

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def get(self, key, default=None):
        return getattr(self, key, default)

@login_manager.user_loader
def load_user(user_id):
    try:
        db = get_mongo_db()
        if not db:
            return None
        
        user_doc = db.users.find_one({'_id': user_id})
        if user_doc:
            return User(
                id=user_doc['_id'],
                email=user_doc['email'],
                username=user_doc['_id'],
                role=user_doc.get('role', 'personal'),
                display_name=user_doc.get('display_name'),
                is_admin=user_doc.get('is_admin', False),
                setup_complete=user_doc.get('setup_complete', False),
                coin_balance=user_doc.get('coin_balance', 0),
                language=user_doc.get('language', 'en'),
                dark_mode=user_doc.get('dark_mode', False)
            )
        return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {str(e)}")
        return None

@babel.localeselector
def get_locale():
    # Check URL parameter first
    if request.args.get('lang'):
        session['lang'] = request.args.get('lang')
    
    # Check session
    if 'lang' in session and session['lang'] in app.config['LANGUAGES']:
        return session['lang']
    
    # Check user preference if logged in
    if current_user.is_authenticated:
        return getattr(current_user, 'language', 'en')
    
    # Fall back to browser preference
    return request.accept_languages.best_match(app.config['LANGUAGES'].keys()) or 'en'

# Import and register blueprints
from users import users_bp
from personal import personal_bp
from dashboard.routes import dashboard_bp

app.register_blueprint(users_bp)
app.register_blueprint(personal_bp)
app.register_blueprint(dashboard_bp)

# Global template variables
@app.context_processor
def inject_globals():
    return {
        't': trans,
        'lang': session.get('lang', 'en'),
        'format_currency': format_currency,
        'format_date': format_date,
        'current_year': datetime.now().year,
        'LINKEDIN_URL': 'https://linkedin.com/company/ficore-africa',
        'TWITTER_URL': 'https://twitter.com/ficore_africa',
        'FACEBOOK_URL': 'https://facebook.com/ficore.africa'
    }

# Language switching route
@app.route('/set_language/<language>')
def set_language(language):
    if language in app.config['LANGUAGES']:
        session['lang'] = language
        session.permanent = True
    return redirect(request.referrer or url_for('index'))

# Main routes
@app.route('/')
def index():
    """Homepage route that serves different content based on user role."""
    if current_user.is_authenticated:
        if current_user.role == 'personal':
            # Personal users see personal finance tools
            return render_template('personal/GENERAL/index.html', 
                                 courses=app.config.get('COURSES', []),
                                 t=trans, 
                                 lang=session.get('lang', 'en'))
        elif current_user.role == 'trader':
            # Traders see business tools
            return render_template('general/home.html', 
                                 t=trans, 
                                 lang=session.get('lang', 'en'))
        elif current_user.role == 'admin':
            # Admins can see everything - redirect to admin dashboard
            return redirect(url_for('admin_blueprint.dashboard'))
        elif current_user.role == 'agent':
            # Agents see agent dashboard
            return redirect(url_for('agents_bp.dashboard'))
    
    # Non-authenticated users see general homepage
    return render_template('general/home.html', 
                         t=trans, 
                         lang=session.get('lang', 'en'))

@app.route('/general_dashboard')
@login_required
@requires_role(['personal', 'admin'])
def general_dashboard():
    """General dashboard for personal finance users."""
    try:
        db = get_mongo_db()
        if not db:
            flash(trans('general_database_error', default='Database connection error'), 'danger')
            return redirect(url_for('index'))
        
        # Determine query based on user role
        query = {} if is_admin() else {'user_id': str(current_user.id)}
        
        # Get latest records from each tool
        latest_financial_health = db.financial_health_scores.find_one(query, sort=[('created_at', -1)])
        latest_budget = db.budgets.find_one(query, sort=[('created_at', -1)])
        latest_bill = db.bills.find_one(query, sort=[('created_at', -1)])
        latest_net_worth = db.net_worth_data.find_one(query, sort=[('created_at', -1)])
        latest_emergency_fund = db.emergency_funds.find_one(query, sort=[('created_at', -1)])
        latest_quiz = db.quiz_responses.find_one(query, sort=[('created_at', -1)])
        
        # Convert to dictionaries for template
        dashboard_data = {
            'financial_health': to_dict_financial_health(latest_financial_health),
            'budget': to_dict_budget(latest_budget),
            'bill': to_dict_bill(latest_bill),
            'net_worth': to_dict_net_worth(latest_net_worth),
            'emergency_fund': to_dict_emergency_fund(latest_emergency_fund),
            'quiz': to_dict_quiz_result(latest_quiz)
        }
        
        return render_template('personal/GENERAL/dashboard.html',
                             dashboard_data=dashboard_data,
                             t=trans,
                             lang=session.get('lang', 'en'))
    
    except Exception as e:
        logger.error(f"Error in general_dashboard: {str(e)}")
        flash(trans('general_dashboard_error', default='Error loading dashboard'), 'danger')
        return redirect(url_for('index'))

@app.route('/about')
def about():
    return render_template('general/about.html', t=trans, lang=session.get('lang', 'en'))

@app.route('/contact')
def contact():
    return render_template('general/contact.html', t=trans, lang=session.get('lang', 'en'))

@app.route('/feedback')
def feedback():
    return render_template('general/feedback.html', t=trans, lang=session.get('lang', 'en'))

@app.route('/acknowledge_consent', methods=['POST'])
def acknowledge_consent():
    """Handle consent acknowledgment."""
    try:
        session['consent_acknowledged'] = True
        session.permanent = True
        return '', 204
    except Exception as e:
        logger.error(f"Error acknowledging consent: {str(e)}")
        return jsonify({'error': 'Failed to acknowledge consent'}), 400

@app.route('/notifications')
@login_required
def notifications():
    """Get user notifications."""
    try:
        # Placeholder for notifications - implement based on your needs
        notifications = []
        return jsonify(notifications)
    except Exception as e:
        logger.error(f"Error getting notifications: {str(e)}")
        return jsonify({'error': 'Failed to load notifications'}), 500

@app.route('/notification_count')
@login_required
def notification_count():
    """Get notification count."""
    try:
        # Placeholder for notification count - implement based on your needs
        count = 0
        return jsonify({'count': count})
    except Exception as e:
        logger.error(f"Error getting notification count: {str(e)}")
        return jsonify({'count': 0})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html', t=trans, lang=session.get('lang', 'en')), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html', t=trans, lang=session.get('lang', 'en')), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html', t=trans, lang=session.get('lang', 'en')), 403

# Session management
@app.before_request
def before_request():
    """Handle session management before each request."""
    try:
        # Create session ID if it doesn't exist
        if 'sid' not in session:
            create_anonymous_session()
        
        # Make session permanent
        session.permanent = True
        
        # Set default language if not set
        if 'lang' not in session:
            session['lang'] = 'en'
            
    except Exception as e:
        logger.error(f"Error in before_request: {str(e)}")

@app.teardown_appcontext
def close_db(error):
    """Close database connections on teardown."""
    try:
        if hasattr(g, 'db'):
            g.db.client.close()
    except Exception as e:
        logger.error(f"Error closing database: {str(e)}")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)