import re
import logging
import uuid
from datetime import datetime
from flask import session, has_request_context, current_app, g
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from translations import trans

# Set up logging with session support
root_logger = logging.getLogger('ficore_app')

class SessionFormatter(logging.Formatter):
    def format(self, record):
        record.session_id = getattr(record, 'session_id', 'no_session_id')
        return super().format(record)

class SessionAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        kwargs['extra'] = kwargs.get('extra', {})
        session_id = 'no-session-id'
        try:
            if has_request_context():
                session_id = session.get('sid', 'no-session-id')
            else:
                session_id = 'no-request-context'
        except Exception as e:
            session_id = 'session-error'
            kwargs['extra']['session_error'] = str(e)
        kwargs['extra']['session_id'] = session_id
        return msg, kwargs

logger = SessionAdapter(root_logger, {})

def create_anonymous_session():
    """Create a guest session for anonymous access."""
    try:
        session['sid'] = str(uuid.uuid4())
        session['is_anonymous'] = True
        session['created_at'] = datetime.utcnow().isoformat()
        # Set default language if not already set
        if 'lang' not in session:
            session['lang'] = 'en'
        logger.info(f"{trans('general_anonymous_session_created', default='Created anonymous session')}: {session['sid']}")
    except Exception as e:
        logger.error(f"{trans('general_anonymous_session_error', default='Error creating anonymous session')}: {str(e)}", exc_info=True)

def trans_function(key, lang=None, **kwargs):
    """
    Translation function wrapper for backward compatibility.
    This function provides the same interface as the old trans_function.
    
    Args:
        key: Translation key
        lang: Language code ('en', 'ha'). Defaults to session['lang'] or 'en'
        **kwargs: String formatting parameters
    
    Returns:
        Translated string with formatting applied
    """
    try:
        return trans(key, lang=lang, **kwargs)
    except Exception as e:
        logger.error(f"{trans('general_translation_error', default='Translation error for key')} '{key}': {str(e)}", exc_info=True)
        return key

def is_valid_email(email):
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
    
    Returns:
        bool: True if email is valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email.strip()) is not None

def get_mongo_db():
    """
    Get MongoDB database connection.
    
    Returns:
        Database object or None if connection fails
    """
    try:
        if hasattr(current_app, 'config') and 'MONGO_CLIENT' in current_app.config:
            client = current_app.config['MONGO_CLIENT']
            if client:
                return client.ficodb
        
        # Fallback: create new connection
        from extensions import mongo_client
        if mongo_client:
            return mongo_client.ficodb
        
        logger.error(trans('general_no_mongo_client', default='No MongoDB client available'))
        return None
    except Exception as e:
        logger.error(f"{trans('general_mongo_connection_error', default='Error getting MongoDB connection')}: {str(e)}", exc_info=True)
        return None

def close_mongo_db():
    """
    Close MongoDB connection.
    """
    try:
        if hasattr(current_app, 'config') and 'MONGO_CLIENT' in current_app.config:
            client = current_app.config['MONGO_CLIENT']
            if client:
                client.close()
                logger.info(trans('general_mongo_connection_closed', default='MongoDB connection closed'))
    except Exception as e:
        logger.error(f"{trans('general_mongo_close_error', default='Error closing MongoDB connection')}: {str(e)}", exc_info=True)

def get_limiter(app):
    """
    Initialize and return Flask-Limiter instance.
    
    Args:
        app: Flask application instance
    
    Returns:
        Limiter instance
    """
    try:
        limiter = Limiter(
            app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://"
        )
        logger.info(trans('general_rate_limiter_initialized', default='Rate limiter initialized'))
        return limiter
    except Exception as e:
        logger.error(f"{trans('general_rate_limiter_error', default='Error initializing rate limiter')}: {str(e)}", exc_info=True)
        # Return a mock limiter that does nothing
        class MockLimiter:
            def limit(self, *args, **kwargs):
                def decorator(f):
                    return f
                return decorator
        return MockLimiter()

def get_mail(app):
    """
    Initialize and return Flask-Mail instance.
    
    Args:
        app: Flask application instance
    
    Returns:
        Mail instance
    """
    try:
        mail = Mail(app)
        logger.info(trans('general_mail_service_initialized', default='Mail service initialized'))
        return mail
    except Exception as e:
        logger.error(f"{trans('general_mail_service_error', default='Error initializing mail service')}: {str(e)}", exc_info=True)
        return None

def requires_role(role):
    """
    Decorator to require specific user role.
    
    Args:
        role: Required role (e.g., 'admin', 'agent', 'personal') or list of roles
    
    Returns:
        Decorator function
    """
    def decorator(f):
        from functools import wraps
        from flask_login import current_user
        from flask import redirect, url_for, flash
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash(trans('general_login_required', default='Please log in to access this page.'), 'warning')
                return redirect(url_for('users_blueprint.login'))
            
            # Allow admins to access all tools
            if is_admin():
                return f(*args, **kwargs)
            
            # Handle both single role and list of roles
            allowed_roles = role if isinstance(role, list) else [role]
            if current_user.role not in allowed_roles:
                flash(trans('general_access_denied', default='You do not have permission to access this page.'), 'danger')
                return redirect(url_for('dashboard.index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_coin_balance(required_amount=1, user_id=None):
    """
    Check if user has sufficient coin balance.
    
    Args:
        required_amount: Required coin amount (default: 1)
        user_id: User ID (optional, will use current_user if not provided)
    
    Returns:
        bool: True if user has sufficient balance, False otherwise
    """
    try:
        from flask_login import current_user
        
        if user_id is None and current_user.is_authenticated:
            user_id = current_user.id
        
        if not user_id:
            return False
        
        db = get_mongo_db()
        if not db:
            return False
        
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            return False
        
        coin_balance = user.get('coin_balance', 0)
        return coin_balance >= required_amount
    except Exception as e:
        logger.error(f"{trans('general_coin_balance_check_error', default='Error checking coin balance for user')} {user_id}: {str(e)}", exc_info=True)
        return False

def get_user_query(user_id):
    """
    Get user query for MongoDB operations.
    
    Args:
        user_id: User ID
    
    Returns:
        dict: MongoDB query for user
    """
    return {'_id': user_id}

def is_admin():
    """
    Check if current user is admin.
    
    Returns:
        bool: True if current user is admin, False otherwise
    """
    try:
        from flask_login import current_user
        return current_user.is_authenticated and (current_user.role == 'admin' or getattr(current_user, 'is_admin', False))
    except Exception:
        return False

def format_currency(amount, currency='₦', lang=None):
    """
    Format currency amount with proper locale.
    
    Args:
        amount: Amount to format
        currency: Currency symbol (default: '₦')
        lang: Language code for formatting
    
    Returns:
        Formatted currency string
    """
    try:
        if lang is None:
            lang = session.get('lang', 'en') if has_request_context() else 'en'
        
        amount = float(amount) if amount is not None else 0
        
        if amount.is_integer():
            return f"{currency}{int(amount):,}"
        return f"{currency}{amount:,.2f}"
    except (TypeError, ValueError) as e:
        logger.warning(f"{trans('general_currency_format_error', default='Error formatting currency')} {amount}: {str(e)}")
        return f"{currency}0"

def format_date(date_obj, lang=None, format_type='short'):
    """
    Format date according to language preference.
    
    Args:
        date_obj: Date object to format
        lang: Language code
        format_type: 'short', 'long', or 'iso'
    
    Returns:
        Formatted date string
    """
    try:
        if lang is None:
            lang = session.get('lang', 'en') if has_request_context() else 'en'
        
        if not date_obj:
            return ''
        
        if isinstance(date_obj, str):
            try:
                date_obj = datetime.strptime(date_obj, '%Y-%m-%d')
            except ValueError:
                try:
                    date_obj = datetime.fromisoformat(date_obj.replace('Z', '+00:00'))
                except ValueError:
                    return date_obj
        
        if format_type == 'iso':
            return date_obj.strftime('%Y-%m-%d')
        elif format_type == 'long':
            if lang == 'ha':
                return date_obj.strftime('%d %B %Y')
            else:
                return date_obj.strftime('%B %d, %Y')
        else:  # short format
            if lang == 'ha':
                return date_obj.strftime('%d/%m/%Y')
            else:
                return date_obj.strftime('%m/%d/%Y')
    except Exception as e:
        logger.warning(f"{trans('general_date_format_error', default='Error formatting date')} {date_obj}: {str(e)}")
        return str(date_obj) if date_obj else ''

def sanitize_input(input_string, max_length=None):
    """
    Sanitize user input to prevent XSS and other attacks.
    
    Args:
        input_string: String to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized string
    """
    if not input_string:
        return ''
    
    # Convert to string and strip whitespace
    sanitized = str(input_string).strip()
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', sanitized)
    
    # Limit length if specified
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized

def generate_unique_id(prefix=''):
    """
    Generate a unique identifier.
    
    Args:
        prefix: Optional prefix for the ID
    
    Returns:
        Unique identifier string
    """
    unique_id = str(uuid.uuid4())
    if prefix:
        return f"{prefix}_{unique_id}"
    return unique_id

def validate_required_fields(data, required_fields):
    """
    Validate that all required fields are present and not empty.
    
    Args:
        data: Dictionary of data to validate
        required_fields: List of required field names
    
    Returns:
        tuple: (is_valid, missing_fields)
    """
    missing_fields = []
    
    for field in required_fields:
        if field not in data or not data[field] or str(data[field]).strip() == '':
            missing_fields.append(field)
    
    return len(missing_fields) == 0, missing_fields

def get_user_language():
    """
    Get the current user's language preference.
    
    Returns:
        Language code ('en' or 'ha')
    """
    try:
        if has_request_context():
            return session.get('lang', 'en')
        return 'en'
    except Exception:
        return 'en'

def log_user_action(action, details=None, user_id=None):
    """
    Log user action for audit purposes.
    
    Args:
        action: Action performed
        details: Additional details about the action
        user_id: User ID (optional, will use current_user if not provided)
    """
    try:
        from flask_login import current_user
        
        if user_id is None and current_user.is_authenticated:
            user_id = current_user.id
        
        session_id = session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'
        
        log_entry = {
            'user_id': user_id,
            'session_id': session_id,
            'action': action,
            'details': details or {},
            'timestamp': datetime.utcnow(),
            'ip_address': None,
            'user_agent': None
        }
        
        if has_request_context():
            from flask import request
            log_entry['ip_address'] = request.remote_addr
            log_entry['user_agent'] = request.headers.get('User-Agent')
        
        db = get_mongo_db()
        if db:
            db.audit_logs.insert_one(log_entry)
        
        logger.info(f"{trans('general_user_action_logged', default='User action logged')}: {action} by user {user_id}")
    except Exception as e:
        logger.error(f"{trans('general_user_action_log_error', default='Error logging user action')}: {str(e)}", exc_info=True)

# Data conversion functions for backward compatibility
def to_dict_financial_health(record):
    """Convert financial health record to dictionary."""
    if not record:
        return {'score': None, 'status': None}
    return {
        'score': record.get('score'),
        'status': record.get('status'),
        'debt_to_income': record.get('debt_to_income'),
        'savings_rate': record.get('savings_rate'),
        'interest_burden': record.get('interest_burden'),
        'badges': record.get('badges', []),
        'created_at': record.get('created_at')
    }

def to_dict_budget(record):
    """Convert budget record to dictionary."""
    if not record:
        return {'surplus_deficit': None, 'savings_goal': None}
    return {
        'income': record.get('income', 0),
        'fixed_expenses': record.get('fixed_expenses', 0),
        'variable_expenses': record.get('variable_expenses', 0),
        'savings_goal': record.get('savings_goal', 0),
        'surplus_deficit': record.get('surplus_deficit', 0),
        'housing': record.get('housing', 0),
        'food': record.get('food', 0),
        'transport': record.get('transport', 0),
        'dependents': record.get('dependents', 0),
        'miscellaneous': record.get('miscellaneous', 0),
        'others': record.get('others', 0),
        'created_at': record.get('created_at')
    }

def to_dict_bill(record):
    """Convert bill record to dictionary."""
    if not record:
        return {'amount': None, 'status': None}
    return {
        'id': str(record.get('_id', '')),
        'bill_name': record.get('bill_name', ''),
        'amount': record.get('amount', 0),
        'due_date': record.get('due_date', ''),
        'frequency': record.get('frequency', ''),
        'category': record.get('category', ''),
        'status': record.get('status', ''),
        'send_email': record.get('send_email', False),
        'reminder_days': record.get('reminder_days'),
        'user_email': record.get('user_email', ''),
        'first_name': record.get('first_name', '')
    }

def to_dict_net_worth(record):
    """Convert net worth record to dictionary."""
    if not record:
        return {'net_worth': None, 'total_assets': None}
    return {
        'cash_savings': record.get('cash_savings', 0),
        'investments': record.get('investments', 0),
        'property': record.get('property', 0),
        'loans': record.get('loans', 0),
        'total_assets': record.get('total_assets', 0),
        'total_liabilities': record.get('total_liabilities', 0),
        'net_worth': record.get('net_worth', 0),
        'badges': record.get('badges', []),
        'created_at': record.get('created_at')
    }

def to_dict_emergency_fund(record):
    """Convert emergency fund record to dictionary."""
    if not record:
        return {'target_amount': None, 'savings_gap': None}
    return {
        'monthly_expenses': record.get('monthly_expenses', 0),
        'monthly_income': record.get('monthly_income', 0),
        'current_savings': record.get('current_savings', 0),
        'risk_tolerance_level': record.get('risk_tolerance_level', ''),
        'dependents': record.get('dependents', 0),
        'timeline': record.get('timeline', 0),
        'recommended_months': record.get('recommended_months', 0),
        'target_amount': record.get('target_amount', 0),
        'savings_gap': record.get('savings_gap', 0),
        'monthly_savings': record.get('monthly_savings', 0),
        'percent_of_income': record.get('percent_of_income'),
        'badges': record.get('badges', []),
        'created_at': record.get('created_at')
    }

def to_dict_learning_progress(record):
    """Convert learning progress record to dictionary."""
    if not record:
        return {'lessons_completed': [], 'quiz_scores': {}}
    return {
        'course_id': record.get('course_id', ''),
        'lessons_completed': record.get('lessons_completed', []),
        'quiz_scores': record.get('quiz_scores', {}),
        'current_lesson': record.get('current_lesson')
    }

def to_dict_quiz_result(record):
    """Convert quiz result record to dictionary."""
    if not record:
        return {'personality': None, 'score': None}
    return {
        'personality': record.get('personality', ''),
        'score': record.get('score', 0),
        'badges': record.get('badges', []),
        'insights': record.get('insights', []),
        'tips': record.get('tips', []),
        'created_at': record.get('created_at')
    }

def to_dict_news_article(record):
    """Convert news article record to dictionary."""
    if not record:
        return {'title': None, 'content': None}
    return {
        'id': str(record.get('_id', '')),
        'title': record.get('title', ''),
        'content': record.get('content', ''),
        'source_type': record.get('source_type', ''),
        'source_link': record.get('source_link'),
        'published_at': record.get('published_at'),
        'category': record.get('category'),
        'is_verified': record.get('is_verified', False),
        'is_active': record.get('is_active', True)
    }

def to_dict_tax_rate(record):
    """Convert tax rate record to dictionary."""
    if not record:
        return {'rate': None, 'description': None}
    return {
        'id': str(record.get('_id', '')),
        'role': record.get('role', ''),
        'min_income': record.get('min_income', 0),
        'max_income': record.get('max_income'),
        'rate': record.get('rate', 0),
        'description': record.get('description', '')
    }

def to_dict_payment_location(record):
    """Convert payment location record to dictionary."""
    if not record:
        return {'name': None, 'address': None}
    return {
        'id': str(record.get('_id', '')),
        'name': record.get('name', ''),
        'address': record.get('address', ''),
        'contact': record.get('contact', ''),
        'coordinates': record.get('coordinates')
    }

def to_dict_tax_reminder(record):
    """Convert tax reminder record to dictionary."""
    if not record:
        return {'tax_type': None, 'amount': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'tax_type': record.get('tax_type', ''),
        'due_date': record.get('due_date'),
        'amount': record.get('amount', 0),
        'status': record.get('status', ''),
        'created_at': record.get('created_at'),
        'notification_id': record.get('notification_id'),
        'sent_at': record.get('sent_at'),
        'payment_location_id': record.get('payment_location_id')
    }

# Export all functions for backward compatibility
__all__ = [
    'create_anonymous_session',
    'trans_function',
    'is_valid_email',
    'get_mongo_db',
    'close_mongo_db',
    'get_limiter',
    'get_mail',
    'requires_role',
    'check_coin_balance',
    'get_user_query',
    'is_admin',
    'format_currency',
    'format_date',
    'sanitize_input',
    'generate_unique_id',
    'validate_required_fields',
    'get_user_language',
    'log_user_action',
    'to_dict_financial_health',
    'to_dict_budget',
    'to_dict_bill',
    'to_dict_net_worth',
    'to_dict_emergency_fund',
    'to_dict_learning_progress',
    'to_dict_quiz_result',
    'to_dict_news_article',
    'to_dict_tax_rate',
    'to_dict_payment_location',
    'to_dict_tax_reminder'
]