import re
import logging
import uuid
import os
import certifi
from datetime import datetime
from flask import session, has_request_context, current_app, url_for, request
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from translations import trans
import requests
from werkzeug.routing import BuildError
import time
from wtforms import ValidationError

# Flask extensions
from flask_login import LoginManager
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel
from flask_compress import Compress

# Initialize extensions
login_manager = LoginManager()
flask_session = Session()
csrf = CSRFProtect()
babel = Babel()
compress = Compress()
limiter = Limiter(key_func=get_remote_address, default_limits=['200 per day', '50 per hour'], storage_uri='memory://')

# Set up logging with session support
root_logger = logging.getLogger('ficore_app')
root_logger.setLevel(logging.DEBUG)

class SessionFormatter(logging.Formatter):
    def format(self, record):
        record.session_id = getattr(record, 'session_id', 'no_session_id')
        record.ip_address = getattr(record, 'ip_address', 'unknown')
        record.user_role = getattr(record, 'user_role', 'anonymous')
        return super().format(record)

class SessionAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        kwargs['extra'] = kwargs.get('extra', {})
        session_id = 'no-session-id'
        ip_address = 'unknown'
        user_role = 'anonymous'
        try:
            if has_request_context():
                session_id = session.get('sid', 'no-session-id')
                ip_address = request.remote_addr
                user_role = current_user.role if current_user.is_authenticated else 'anonymous'
            else:
                session_id = f'non-request-{str(uuid.uuid4())[:8]}'
        except Exception as e:
            session_id = f'session-error-{str(uuid.uuid4())[:8]}'
            kwargs['extra']['session_error'] = str(e)
        kwargs['extra']['session_id'] = session_id
        kwargs['extra']['ip_address'] = ip_address
        kwargs['extra']['user_role'] = user_role
        return msg, kwargs

logger = SessionAdapter(root_logger, {})

# Tool/navigation lists with endpoints
_PERSONAL_TOOLS = [
    {
        "endpoint": "personal.budget.main",
        "label": "Budget",
        "label_key": "budget_budget_planner",
        "description_key": "budget_budget_desc",
        "tooltip_key": "budget_tooltip",
        "icon": "bi-wallet"
    },
    {
        "endpoint": "personal.bill.main",
        "label": "Bills",
        "label_key": "bill_bill_planner",
        "description_key": "bill_bill_desc",
        "tooltip_key": "bill_tooltip",
        "icon": "bi-receipt"
    },
    {
        "endpoint": "personal.shopping.main",
        "label": "Shopping",
        "label_key": "shopping_management",
        "description_key": "shopping_management_desc",
        "tooltip_key": "shopping_tooltip",
        "icon": "bi-cart"
    },
    {
        "endpoint": "credits.history",
        "label": "Ficore Credits",
        "label_key": "credits_your_wallet",
        "description_key": "credits_your_wallet_desc",
        "tooltip_key": "credits_your_wallet_tooltip",
        "icon": "bi-coin"
    },
]

_PERSONAL_NAV = [
    {
        "endpoint": "personal.index",
        "label": "Home",
        "label_key": "general_home",
        "description_key": "general_home_desc",
        "tooltip_key": "general_home_tooltip",
        "icon": "bi-house"
    },
    {
        "endpoint": "personal.bill.main",
        "label": "Bills",
        "label_key": "bill_bill_planner",
        "description_key": "bill_bill_desc",
        "tooltip_key": "bill_tooltip",
        "icon": "bi-receipt"
    },   
    {
        "endpoint": "personal.shopping.main",
        "label": "Shopping",
        "label_key": "shopping_management",
        "description_key": "shopping_management_desc",
        "tooltip_key": "shopping_tooltip",
        "icon": "bi-cart"
    },
    {
        "endpoint": "settings.profile",
        "label": "Profile",
        "label_key": "profile_settings",
        "description_key": "profile_settings_desc",
        "tooltip_key": "profile_tooltip",
        "icon": "bi-person"
    },
]

_PERSONAL_EXPLORE_FEATURES = [
    {
        "endpoint": "personal.budget.main",
        "label": "Budget",
        "label_key": "budget_budget_planner",
        "description_key": "budget_budget_desc",
        "tooltip_key": "budget_tooltip",
        "icon": "bi-wallet"
    },
    {
        "endpoint": "personal.bill.main",
        "label": "Bills",
        "label_key": "bill_bill_planner",
        "description_key": "bill_bill_desc",
        "tooltip_key": "bill_tooltip",
        "icon": "bi-receipt"
    },
    {
        "endpoint": "personal.shopping.main",
        "label": "Shopping",
        "label_key": "shopping_management",
        "description_key": "shopping_management_desc",
        "tooltip_key": "shopping_tooltip",
        "icon": "bi-cart"
    },  
    {
        "endpoint": "credits.request_credits",
        "label": "Ficore Credits",
        "label_key": "credits_dashboard",
        "description_key": "credits_dashboard_desc",
        "tooltip_key": "credits_tooltip",
        "icon": "bi-coin"
    },   
    {
        "endpoint": "credits.history",
        "label": "Ficore Credits",
        "label_key": "credits_your_wallet",
        "description_key": "credits_your_wallet_desc",
        "tooltip_key": "credits_your_wallet_tooltip",
        "icon": "bi-coin"
    },
    {
        "endpoint": "taxation_bp.calculate_tax",
        "label": "Taxation",
        "label_key": "taxation_calculator",
        "description_key": "taxation_calculator_desc",
        "tooltip_key": "taxation_tooltip",
        "icon": "bi-calculator"
    },
    {
        "endpoint": "reports.index",
        "label": "Reports",
        "label_key": "personal_reports",
        "description_key": "personal_reports_desc",
        "tooltip_key": "personal_reports_tooltip",
        "icon": "bi-journal-minus"
    },
]

_BUSINESS_TOOLS = [ 
    {
        "endpoint": "debtors.index",
        "label": "They Owe",
        "label_key": "debtors_dashboard",
        "description_key": "debtors_dashboard_desc",
        "tooltip_key": "debtors_tooltip",
        "icon": "bi-person-plus"
    },
    {
        "endpoint": "creditors.index",
        "label": "I Owe",
        "label_key": "creditors_dashboard",
        "description_key": "creditors_dashboard_desc",
        "tooltip_key": "creditors_tooltip",
        "icon": "bi-arrow-up-circle"
    },    
    {
        "endpoint": "receipts.index",
        "label": "MoneyIn",
        "label_key": "receipts_dashboard",
        "description_key": "receipts_dashboard",
        "tooltip_key": "receipts_tooltip",
        "icon": "bi-cash-coin"
    },    
    {
        "endpoint": "payments.index",
        "label": "MoneyOut",
        "label_key": "payments_dashboard",
        "description_key": "payments_dashboard",
        "tooltip_key": "payments_tooltip",
        "icon": "bi-calculator"
    }, 
    {
        "endpoint": "credits.history",
        "label": "Ficore Credits",
        "label_key": "credits_your_wallet",
        "description_key": "credits_your_wallet_desc",
        "tooltip_key": "credits_your_wallet_tooltip",
        "icon": "bi-coin"
    },    
    {
        "endpoint": "reports.index",
        "label": "Reports",
        "label_key": "business_reports",
        "description_key": "business_reports_desc",
        "tooltip_key": "business_reports_tooltip",
        "icon": "bi-journal-minus"
    },
]

_BUSINESS_NAV = [
    {
        "endpoint": "general_bp.home",
        "label": "Home",
        "label_key": "general_business_home",
        "description_key": "general_business_home_desc",
        "tooltip_key": "general_business_home_tooltip",
        "icon": "bi-house"
    },
    {
        "endpoint": "debtors.index",
        "label": "They Owe",
        "label_key": "debtors_dashboard",
        "description_key": "debtors_dashboard_desc",
        "tooltip_key": "debtors_tooltip",
        "icon": "bi-person-plus"
    },
    {
        "endpoint": "credits.history",
        "label": "Ficore Credits",
        "label_key": "credits_your_wallet",
        "description_key": "credits_your_wallet_desc",
        "tooltip_key": "credits_your_wallet_tooltip",
        "icon": "bi-coin"
    },
    {
        "endpoint": "settings.profile",
        "label": "Profile",
        "label_key": "profile_settings",
        "description_key": "profile_settings_desc",
        "tooltip_key": "profile_tooltip",
        "icon": "bi-person"
    },
]

_BUSINESS_EXPLORE_FEATURES = [
    {
        "endpoint": "receipts.index",
        "label": "MoneyIn",
        "label_key": "receipts_dashboard",
        "description_key": "receipts_dashboard",
        "tooltip_key": "receipts_tooltip",
        "icon": "bi-cash-coin"
    }, 
    {
        "endpoint": "payments.index",
        "label": "MoneyOut",
        "label_key": "payments_dashboard",
        "description_key": "payments_dashboard",
        "tooltip_key": "payments_tooltip",
        "icon": "bi-calculator"
    },
    {
        "endpoint": "taxation_bp.calculate_tax",
        "label": "Taxation",
        "label_key": "taxation_calculator",
        "description_key": "taxation_calculator_desc",
        "tooltip_key": "taxation_tooltip",
        "icon": "bi-calculator"
    },
    {
        "endpoint": "debtors.index",
        "label": "They Owe",
        "label_key": "debtors_dashboard",
        "description_key": "debtors_dashboard_desc",
        "tooltip_key": "debtors_tooltip",
        "icon": "bi-person-plus"
    },
    {
        "endpoint": "creditors.index",
        "label": "I Owe",
        "label_key": "creditors_dashboard",
        "description_key": "creditors_dashboard_desc",
        "tooltip_key": "creditors_tooltip",
        "icon": "bi-arrow-up-circle"
    },
    {
        "endpoint": "credits.request_credits",
        "label": "Ficore Credits",
        "label_key": "credits_dashboard",
        "description_key": "credits_dashboard_desc",
        "tooltip_key": "credits_tooltip",
        "icon": "bi-coin"
    },
    {
        "endpoint": "reports.index",
        "label": "Reports",
        "label_key": "business_reports",
        "description_key": "business_reports_desc",
        "tooltip_key": "business_reports_tooltip",
        "icon": "bi-journal-minus"
    },
]

_AGENT_TOOLS = [
    {
        "endpoint": "agents_bp.agent_portal",
        "label": "Agent Portal",
        "label_key": "agents_dashboard",
        "description_key": "agents_dashboard_desc",
        "tooltip_key": "agents_tooltip",
        "icon": "bi-person-workspace"
    },
    {
        "endpoint": "agents_bp.manage_credits",
        "label": "Ficore Credits",
        "label_key": "credits_dashboard",
        "description_key": "credits_dashboard_desc",
        "tooltip_key": "credits_tooltip",
        "icon": "bi-coin"
    },
]

_AGENT_NAV = [
    {
        "endpoint": "agents_bp.agent_portal",
        "label": "Agent Portal",
        "label_key": "agents_dashboard",
        "description_key": "agents_dashboard_desc",
        "tooltip_key": "agents_tooltip",
        "icon": "bi-person-workspace"
    },
    {
        "endpoint": "agents_bp.agent_portal",
        "label": "My Activity",
        "label_key": "agents_my_activity",
        "description_key": "agents_my_activity_desc",
        "tooltip_key": "agents_my_activity_tooltip",
        "icon": "bi-person-workspace"
    },
    {
        "endpoint": "settings.profile",
        "label": "Profile",
        "label_key": "profile_settings",
        "description_key": "profile_settings_desc",
        "tooltip_key": "profile_tooltip",
        "icon": "bi-person"
    },
]

_AGENT_EXPLORE_FEATURES = [
    {
        "endpoint": "agents_bp.agent_portal",
        "label": "Agent Portal",
        "label_key": "agents_dashboard",
        "description_key": "agents_dashboard_desc",
        "tooltip_key": "agents_tooltip",
        "icon": "bi-person-workspace"
    },
    {
        "endpoint": "agents_bp.manage_credits",
        "label": "Ficore Credits",
        "label_key": "credits_dashboard",
        "description_key": "credits_dashboard_desc",
        "tooltip_key": "credits_tooltip",
        "icon": "bi-coin"
    },
]

_ADMIN_TOOLS = [
    {
        "endpoint": "admin.dashboard",
        "label": "Dashboard",
        "label_key": "admin_dashboard",
        "description_key": "admin_dashboard_desc",
        "tooltip_key": "admin_dashboard_tooltip",
        "icon": "bi-speedometer"
    },
    {
        "endpoint": "admin.manage_users",
        "label": "Manage Users",
        "label_key": "admin_manage_users",
        "description_key": "admin_manage_users_desc",
        "tooltip_key": "admin_manage_users_tooltip",
        "icon": "bi-people"
    },
    {
        "endpoint": "admin.view_credit_requests",
        "label": "Credit Ficore Credits",
        "label_key": "admin_ficore_credits",
        "description_key": "admin_ficore_credits_desc",
        "tooltip_key": "admin_ficore_credits_tooltip",
        "icon": "bi-coin"
    },
]

_ADMIN_NAV = [
    {
        "endpoint": "admin.dashboard",
        "label": "Dashboard",
        "label_key": "admin_dashboard",
        "description_key": "admin_dashboard_desc",
        "tooltip_key": "admin_dashboard_tooltip",
        "icon": "bi-speedometer"
    },
    {
        "endpoint": "admin.view_credit_requests",
        "label": "Credit Ficore Credits",
        "label_key": "admin_ficore_credits",
        "description_key": "admin_ficore_credits_desc",
        "tooltip_key": "admin_ficore_credits_tooltip",
        "icon": "bi-coin"
    },
    {
        "endpoint": "admin.manage_users",
        "label": "Manage Users",
        "label_key": "admin_manage_users",
        "description_key": "admin_manage_users_desc",
        "tooltip_key": "admin_manage_users_tooltip",
        "icon": "bi-people"
    },
    {
        "endpoint": "admin.audit",
        "label": "View Audit Logs",
        "label_key": "admin_view_audit_logs",
        "description_key": "admin_view_audit_logs_desc",
        "tooltip_key": "admin_view_audit_logs_tooltip",
        "icon": "bi-file-earmark-text"
    },
]

_ADMIN_EXPLORE_FEATURES = [
    {
        "endpoint": "admin.dashboard",
        "label": "Dashboard",
        "label_key": "admin_dashboard",
        "description_key": "admin_dashboard_desc",
        "tooltip_key": "admin_dashboard_tooltip",
        "icon": "bi-speedometer"
    },
    {
        "endpoint": "admin.manage_users",
        "label": "Manage Users",
        "label_key": "admin_manage_users",
        "description_key": "admin_manage_users_desc",
        "tooltip_key": "admin_manage_users_tooltip",
        "icon": "bi-people"
    },
    {
        "endpoint": "admin.manage_agents",
        "label": "Manage Agents",
        "label_key": "admin_manage_agents",
        "description_key": "admin_manage_agents_desc",
        "tooltip_key": "admin_manage_agents_tooltip",
        "icon": "bi-person-workspace"
    },
    {
        "endpoint": "admin.admin_budgets",
        "label": "Manage Budgets",
        "label_key": "admin_manage_budgets",
        "description_key": "admin_manage_budgets_desc",
        "tooltip_key": "admin_manage_budgets_tooltip",
        "icon": "bi-wallet"
    },
    {
        "endpoint": "admin.admin_bills",
        "label": "Manage Bills",
        "label_key": "admin_manage_bills",
        "description_key": "admin_manage_bills_desc",
        "tooltip_key": "admin_manage_bills_tooltip",
        "icon": "bi-receipt"
    },
]

def get_explore_features():
    """Return explore features for unauthenticated users on the landing page with resolved URLs and ensured label_key."""
    try:
        with current_app.app_context():
            features = [
                {
                    "endpoint": "personal.budget.main",
                    "label": "Budget Planner",
                    "label_key": "budget_budget_planner",
                    "description_key": "budget_budget_desc",
                    "tooltip_key": "budget_tooltip",
                    "icon": "bi-wallet",
                    "category": "Personal"
                },
                {
                    "endpoint": "personal.bill.main",
                    "label": "Bills",
                    "label_key": "bill_bill_planner",
                    "description_key": "bill_bill_desc",
                    "tooltip_key": "bill_tooltip",
                    "icon": "bi-receipt"
                },
                {
                    "endpoint": "personal.shopping.main",
                    "label": "Shopping",
                    "label_key": "shopping_management",
                    "description_key": "shopping_management_desc",
                    "tooltip_key": "shopping_tooltip",
                    "icon": "bi-cart",
                    "category": "Personal"
                },
                {
                    "endpoint": "creditors.index",
                    "label": "I Owe",
                    "label_key": "creditors_dashboard",
                    "description_key": "creditors_dashboard_desc",
                    "tooltip_key": "creditors_tooltip",
                    "icon": "bi-arrow-up-circle",
                    "category": "Business"
                },
                {
                    "endpoint": "debtors.index",
                    "label": "They Owe",
                    "label_key": "debtors_dashboard",
                    "description_key": "debtors_dashboard_desc",
                    "tooltip_key": "debtors_tooltip",
                    "icon": "bi-person-plus",
                    "category": "Business"
                },
                {
                    "endpoint": "receipts.index",
                    "label": "MoneyIn",
                    "label_key": "receipts_dashboard",
                    "description_key": "receipts_dashboard",
                    "tooltip_key": "receipts_tooltip",
                    "icon": "bi-cash-coin"
                }, 
                {
                    "endpoint": "payments.index",
                    "label": "MoneyOut",
                    "label_key": "payments_dashboard",
                    "description_key": "payments_dashboard",
                    "tooltip_key": "payments_tooltip",
                    "icon": "bi-calculator"
                },
                {
                    "endpoint": "agents_bp.agent_portal",
                    "label": "Agent Portal",
                    "label_key": "agents_dashboard",
                    "description_key": "agents_dashboard_desc",
                    "tooltip_key": "agents_tooltip",
                    "icon": "bi-person-workspace",
                    "category": "Agent"
                },
            ]
            required_keys = ['endpoint', 'label', 'label_key', 'description_key', 'tooltip_key', 'icon']
            for feature in features:
                for key in required_keys:
                    if key not in feature:
                        default_value = feature.get('label', 'default_feature').lower().replace(' ', '_') + f'_{key}' if key == 'label_key' else 'default_' + key
                        feature[key] = default_value
                        logger.warning(
                            f"Missing {key} for feature {feature.get('label', 'unknown')}, assigned default: {feature[key]}",
                            extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr if has_request_context() else 'unknown'}
                        )
            return generate_tools_with_urls(features)
    except Exception as e:
        logger.error(f"Error generating explore features: {str(e)}", exc_info=True)
        return []

# Initialize module-level variables
PERSONAL_TOOLS = []
PERSONAL_NAV = []
PERSONAL_EXPLORE_FEATURES = []
BUSINESS_TOOLS = []
BUSINESS_NAV = []
BUSINESS_EXPLORE_FEATURES = []
AGENT_TOOLS = []
AGENT_NAV = []
AGENT_EXPLORE_FEATURES = []
ADMIN_TOOLS = []
ADMIN_NAV = []
ADMIN_EXPLORE_FEATURES = []
ALL_TOOLS = []

def initialize_tools_with_urls(app):
    """
    Initialize all tool/navigation lists with resolved URLs.
    
    Args:
        app: Flask application instance
    """
    global PERSONAL_TOOLS, PERSONAL_NAV, PERSONAL_EXPLORE_FEATURES
    global BUSINESS_TOOLS, BUSINESS_NAV, BUSINESS_EXPLORE_FEATURES
    global AGENT_TOOLS, AGENT_NAV, AGENT_EXPLORE_FEATURES
    global ADMIN_TOOLS, ADMIN_NAV, ADMIN_EXPLORE_FEATURES
    global ALL_TOOLS
    
    try:
        with app.app_context():
            PERSONAL_TOOLS = generate_tools_with_urls(_PERSONAL_TOOLS)
            PERSONAL_NAV = generate_tools_with_urls(_PERSONAL_NAV)
            PERSONAL_EXPLORE_FEATURES = generate_tools_with_urls(_PERSONAL_EXPLORE_FEATURES)
            BUSINESS_TOOLS = generate_tools_with_urls(_BUSINESS_TOOLS)
            BUSINESS_NAV = generate_tools_with_urls(_BUSINESS_NAV)
            BUSINESS_EXPLORE_FEATURES = generate_tools_with_urls(_BUSINESS_EXPLORE_FEATURES)
            AGENT_TOOLS = generate_tools_with_urls(_AGENT_TOOLS)
            AGENT_NAV = generate_tools_with_urls(_AGENT_NAV)
            AGENT_EXPLORE_FEATURES = generate_tools_with_urls(_AGENT_EXPLORE_FEATURES)
            ADMIN_TOOLS = generate_tools_with_urls(_ADMIN_TOOLS)
            ADMIN_NAV = generate_tools_with_urls(_ADMIN_NAV)
            ADMIN_EXPLORE_FEATURES = generate_tools_with_urls(_ADMIN_EXPLORE_FEATURES)
            ALL_TOOLS = (
                PERSONAL_TOOLS +
                BUSINESS_TOOLS +
                AGENT_TOOLS +
                ADMIN_TOOLS +
                generate_tools_with_urls([{
                    "endpoint": "admin.dashboard",
                    "label": "Management",
                    "label_key": "admin_dashboard",
                    "description_key": "admin_dashboard_desc",
                    "tooltip_key": "admin_dashboard_tooltip",
                    "icon": "bi-speedometer"
                }])
            )
            logger.info('Initialized tools and navigation with resolved URLs')
    except Exception as e:
        logger.error(f'Error initializing tools with URLs: {str(e)}', exc_info=True)
        raise

def generate_tools_with_urls(tools):
    """
    Generate a list of tools with resolved URLs and validated icons.
    
    Args:
        tools: List of dictionaries containing 'endpoint' and 'icon' keys
    
    Returns:
        List of dictionaries with 'url' keys added and validated 'icon' fields
    """
    result = []
    for tool in tools:
        try:
            url = url_for(tool['endpoint'], _external=True)
            icon = tool.get('icon', 'bi-question-circle')
            if not icon or not icon.startswith('bi-'):
                logger.warning(f"Invalid or missing icon for tool {tool.get('label', 'unknown')}: {icon}. Using fallback 'bi-question-circle'.")
                icon = 'bi-question-circle'
            result.append({**tool, 'url': url, 'icon': icon})
        except BuildError as e:
            logger.warning(f"Failed to generate URL for endpoint {tool.get('endpoint', 'unknown')}: {str(e)}. Ensure endpoint is defined in blueprint.")
            result.append({**tool, 'url': '#', 'icon': tool.get('icon', 'bi-question-circle')})
        except RuntimeError as e:
            logger.warning(f"Runtime error generating URL for endpoint {tool.get('endpoint', 'unknown')}: {str(e)}")
            result.append({**tool, 'url': '#', 'icon': tool.get('icon', 'bi-question-circle')})
    return result

def get_limiter():
    """
    Return the initialized Flask-Limiter instance.
    
    Returns:
        Limiter: The configured Flask-Limiter instance
    """
    return limiter

def log_tool_usage(action, tool_name=None, details=None, user_id=None, db=None, session_id=None):
    """
    Log tool usage to MongoDB tool_usage collection with improved error handling and session support.
    
    Args:
        action (str): The action performed (e.g., 'main_view', 'add_bill').
        tool_name (str, optional): The name of the tool used. Defaults to action if None.
        details (dict, optional): Additional details about the action.
        user_id (str, optional): ID of the user performing the action.
        db (MongoDB database, optional): MongoDB database instance. If None, fetched via get_mongo_db().
        session_id (str, optional): Session ID for the action.
    
    Raises:
        RuntimeError: If database connection fails or insertion fails.
    """
    try:
        if db is None:
            db = get_mongo_db()
        
        if not action or not isinstance(action, str):
            raise ValueError("Action must be a non-empty string")
        
        effective_session_id = session_id or session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'
        
        log_entry = {
            'tool_name': tool_name or action,
            'user_id': str(user_id) if user_id else None,
            'session_id': effective_session_id,
            'action': details.get('action') if details else None,
            'timestamp': datetime.utcnow(),
            'ip_address': request.remote_addr if has_request_context() else 'unknown',
            'user_agent': request.headers.get('User-Agent') if has_request_context() else 'unknown'
        }
        
        db.tool_usage.insert_one(log_entry)
        logger.info(
            f"Logged tool usage: {action}",
            extra={
                'user_id': user_id or 'unknown',
                'session_id': effective_session_id,
                'ip_address': request.remote_addr if has_request_context() else 'unknown'
            }
        )
    except ValueError as e:
        logger.error(
            f"Invalid input for log_tool_usage: {str(e)}",
            exc_info=True,
            extra={
                'user_id': user_id or 'unknown',
                'session_id': session_id or session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id',
                'ip_address': request.remote_addr if has_request_context() else 'unknown'
            }
        )
        raise
    except Exception as e:
        logger.error(
            f"Failed to log tool usage for action {action}: {str(e)}",
            exc_info=True,
            extra={
                'user_id': user_id or 'unknown',
                'session_id': session_id or session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id',
                'ip_address': request.remote_addr if has_request_context() else 'unknown'
            }
        )
        raise RuntimeError(f"Failed to log tool usage: {str(e)}")

def create_anonymous_session():
    """
    Create a guest session for anonymous access with retry logic.
    """
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with current_app.app_context():
                session['sid'] = str(uuid.uuid4())
                session['is_anonymous'] = True
                session['created_at'] = datetime.utcnow().isoformat()
                if 'lang' not in session:
                    session['lang'] = 'en'
                session.modified = True
                logger.info(
                    f"{trans('general_anonymous_session_created', default='Created anonymous session')}: {session['sid']}",
                    extra={'session_id': session['sid'], 'ip_address': request.remote_addr if has_request_context() else 'unknown'}
                )
                return
        except Exception as e:
            logger.warning(
                f"Attempt {attempt + 1} failed to create anonymous session: {str(e)}",
                exc_info=True,
                extra={'session_id': 'no-session-id', 'ip_address': request.remote_addr if has_request_context() else 'unknown'}
            )
            if attempt == max_retries - 1:
                session['sid'] = f'error-{str(uuid.uuid4())[:8]}'
                session['is_anonymous'] = True
                session.modified = True
                logger.error(
                    f"{trans('general_anonymous_session_error', default='Error creating anonymous session after retries')}: {str(e)}",
                    exc_info=True,
                    extra={'session_id': session['sid'], 'ip_address': request.remote_addr if has_request_context() else 'unknown'}
                )
                return
            time.sleep(0.5)

def clean_currency(value, max_value=10000000000):
    """
    Clean currency input by removing non-numeric characters, handling various currency formats and edge cases.
    
    Args:
        value: Input value to clean (str, int, float, or None)
        max_value: Maximum allowed value (default: 10 billion)
    
    Returns:
        float: Cleaned numeric value
    
    Raises:
        ValidationError: If the input cannot be converted to a valid float or exceeds max_value
    """
    try:
        # Handle None or empty inputs
        if value is None or str(value).strip() == '':
            logger.debug(
                "clean_currency received empty or None input, returning 0.0",
                extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
            )
            return 0.0

        # Handle numeric inputs (int or float)
        if isinstance(value, (int, float)):
            value = float(value)
            if value > max_value:
                logger.warning(
                    f"Currency value exceeds maximum: value={value}, max_value={max_value}",
                    extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
                )
                raise ValidationError(trans('bill_amount_max', default=f"Input cannot exceed {max_value:,}", lang=get_user_language()))
            return value

        # Convert to string and normalize
        value_str = str(value).strip()
        logger.debug(
            f"clean_currency processing input: '{value_str}'",
            extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
        )

        # Remove currency symbols and formatting characters (e.g., commas, spaces)
        cleaned = re.sub(r'[^\d.]', '', value_str.replace('NGN', '').replace('₦', '').replace('$', '').replace('€', '').replace('£', '').replace(',', ''))

        # Handle multiple decimal points
        parts = cleaned.split('.')
        if len(parts) > 2:
            cleaned = parts[0] + '.' + ''.join(parts[1:])

        # Validate the cleaned string
        if not cleaned or cleaned == '.':
            logger.warning(
                f"Invalid currency format after cleaning: original='{value_str}', cleaned='{cleaned}'",
                extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
            )
            raise ValidationError(trans('invalid_currency_format', default='Invalid currency format', lang=get_user_language()))

        # Check for valid numeric format
        if cleaned.count('.') > 1 or cleaned.count('-') > 1 or (cleaned.count('-') == 1 and not cleaned.startswith('-')):
            logger.warning(
                f"Invalid currency format: original='{value_str}', cleaned='{cleaned}', multiple decimals or misplaced negative sign",
                extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
            )
            raise ValidationError(trans('invalid_currency_format', default='Invalid currency format', lang=get_user_language()))

        # Convert to float
        try:
            result = float(cleaned)
            if result < 0:
                logger.warning(
                    f"Negative currency value not allowed: original='{value_str}', cleaned='{cleaned}', result={result}",
                    extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
                )
                raise ValidationError(trans('negative_currency_not_allowed', default='Negative currency values are not allowed', lang=get_user_language()))
            if result > max_value:
                logger.warning(
                    f"Currency value exceeds maximum: original='{value_str}', cleaned='{cleaned}', result={result}, max_value={max_value}",
                    extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
                )
                raise ValidationError(trans('bill_amount_max', default=f"Input cannot exceed {max_value:,}", lang=get_user_language()))
            logger.debug(
                f"clean_currency successfully processed '{value_str}' to {result}",
                extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
            )
            return result
        except ValueError as e:
            logger.warning(
                f"Currency format error: original='{value_str}', cleaned='{cleaned}', error='{str(e)}'",
                extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
            )
            raise ValidationError(trans('invalid_currency_format', default='Invalid currency format', lang=get_user_language()))
    except ValidationError as e:
        raise  # Re-raise ValidationError for form validation
    except Exception as e:
        logger.error(
            f"Unexpected error in clean_currency for value '{value}': {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
        )
        raise ValidationError(trans('invalid_currency_format', default='Invalid currency format', lang=get_user_language()))

def trans_function(key, lang=None, **kwargs):
    """
    Translation function wrapper for backward compatibility.
    
    Args:
        key: Translation key
        lang: Language code ('en', 'ha'). Defaults to session['lang'] or 'en'
        **kwargs: String formatting parameters
    
    Returns:
        Translated string with formatting applied
    """
    try:
        with current_app.app_context():
            translated = trans(key, lang=lang, **kwargs)
            if translated == key:  # Translation missing
                logger.warning(
                    f"Missing translation for key='{key}' in module='general', lang='{lang or session.get('lang', 'en')}'",
                    extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
                )
                return key  # Fallback to the key itself
            return translated
    except Exception as e:
        logger.error(
            f"Translation error for key '{key}': {str(e)}",
            exc_info=True,
            extra={'session_id': session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'}
        )
        return key  # Fallback to the key itself

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
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email.strip()) is not None

def get_mongo_db():
    """
    Get MongoDB database instance with retry logic.
    
    Returns:
        Database object
    """
    max_retries = 3
    retry_delay = 1
    for attempt in range(max_retries):
        try:
            with current_app.app_context():
                if 'mongo' not in current_app.extensions:
                    mongo_uri = os.getenv('MONGO_URI')
                    if not mongo_uri:
                        logger.error("MONGO_URI environment variable not set",
                                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr if has_request_context() else 'unknown'})
                        raise RuntimeError("MONGO_URI environment variable not set")
                    
                    client = MongoClient(
                        mongo_uri,
                        serverSelectionTimeoutMS=5000,
                        tls=True,
                        tlsCAFile=certifi.where() if os.getenv('MONGO_CA_FILE') is None else os.getenv('MONGO_CA_FILE'),
                        maxPoolSize=50,
                        minPoolSize=5
                    )
                    client.admin.command('ping')
                    current_app.extensions['mongo'] = client
                    logger.info("MongoDB client initialized successfully in utils.get_mongo_db",
                               extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr if has_request_context() else 'unknown'})
                
                db = current_app.extensions['mongo']['ficodb']
                db.command('ping')
                return db
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.warning(
                f"Attempt {attempt + 1}/{max_retries} failed to connect to MongoDB: {str(e)}",
                exc_info=True,
                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr if has_request_context() else 'unknown'}
            )
            if attempt == max_retries - 1:
                logger.error(
                    f"Failed to connect to MongoDB after {max_retries} attempts: {str(e)}",
                    exc_info=True,
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr if has_request_context() else 'unknown'}
                )
                raise RuntimeError(f"Failed to connect to MongoDB: {str(e)}")
            time.sleep(retry_delay)
    raise RuntimeError("Failed to connect to MongoDB after retries")

def close_mongo_db():
    """
    No-op function for backward compatibility.
    """
    pass

def get_mail(app):
    """
    Initialize and return Flask-Mail instance.
    
    Args:
        app: Flask application instance
    
    Returns:
        Mail instance
    """
    try:
        with app.app_context():
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
            with current_app.app_context():
                if not current_user.is_authenticated:
                    flash(trans('general_login_required', default='Please log in to access this page.'), 'warning')
                    return redirect(url_for('users.login'))
                if is_admin():
                    return f(*args, **kwargs)
                allowed_roles = role if isinstance(role, list) else [role]
                if current_user.role not in allowed_roles:
                    flash(trans('general_access_denied', default='You do not have permission to access this page.'), 'danger')
                    return redirect(url_for('dashboard.index'))
                return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_ficore_credit_balance(required_amount=1, user_id=None):
    """
    Check if user has sufficient Ficore Credit balance with enhanced logging.
    
    Args:
        required_amount: Required credit amount (default: 1)
        user_id: User ID (optional, will use current_user if not provided)
    
    Returns:
        bool: True if user has sufficient balance, False otherwise
    """
    try:
        with current_app.app_context():
            from flask_login import current_user
            # Validate required_amount
            if not isinstance(required_amount, (int, float)) or required_amount < 0:
                logger.error(
                    f"Invalid required_amount {required_amount} for credit balance check",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id or 'unknown'}
                )
                return False
            
            # Determine user_id
            if user_id is None and current_user.is_authenticated:
                user_id = current_user.id
            if not user_id:
                logger.error(
                    f"No user_id provided and no authenticated user for credit balance check",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': 'unknown'}
                )
                return False
            
            # Validate user_id
            if not isinstance(user_id, str) or not user_id.strip():
                logger.error(
                    f"Invalid user_id format: {user_id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id or 'unknown'}
                )
                return False
            
            db = get_mongo_db()
            if db is None:
                logger.error(
                    f"Failed to connect to MongoDB for credit balance check for user {user_id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id}
                )
                return False
            
            user_query = get_user_query(user_id)
            user = db.users.find_one(user_query)
            if not user:
                logger.error(
                    f"User {user_id} not found for credit balance check",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id}
                )
                return False
            
            current_balance = user.get('ficore_credit_balance', 0)
            if not isinstance(current_balance, (int, float)) or current_balance < 0:
                logger.warning(
                    f"Invalid credit balance for user {user_id}: {current_balance}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id}
                )
                return False
            
            if current_balance < required_amount:
                logger.warning(
                    f"Insufficient credits for user {user_id}: required {required_amount}, available {current_balance}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id}
                )
                return False
            
            logger.debug(
                f"Credit balance check passed for user {user_id}: required {required_amount}, available {current_balance}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id}
            )
            return True
    except Exception as e:
        logger.error(
            f"Unexpected error checking Ficore Credit balance for user {user_id}: {str(e)}",
            exc_info=True,
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id or 'unknown'}
        )
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
        with current_app.app_context():
            from flask_login import current_user
            return current_user.is_authenticated and (current_user.role == 'admin' or getattr(current_user, 'is_admin', False))
    except Exception:
        return False

def format_currency(amount, currency='₦', lang=None, include_symbol=True):
    """
    Format currency amount with proper locale.
    
    Args:
        amount: Amount to format
        currency: Currency symbol (default: '₦')
        lang: Language code for formatting
        include_symbol: Whether to include the currency symbol (default: True)
    
    Returns:
        Formatted currency string
    """
    try:
        with current_app.app_context():
            if lang is None:
                lang = session.get('lang', 'en') if has_request_context() else 'en'
            amount = clean_currency(amount) if isinstance(amount, str) else float(amount) if amount is not None else 0
            if amount.is_integer():
                formatted = f"{int(amount):,}"
            else:
                formatted = f"{amount:,.2f}"
            return f"{currency}{formatted}" if include_symbol else formatted
    except (TypeError, ValueError, ValidationError) as e:
        logger.warning(f"{trans('general_currency_format_error', default='Error formatting currency')} {amount}: {str(e)}")
        return f"{currency}0" if include_symbol else "0"

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
        with current_app.app_context():
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
            else:
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
    sanitized = str(input_string).strip()
    sanitized = re.sub(r'[<>"\']', '', sanitized)
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
        with current_app.app_context():
            return session.get('lang', 'en') if has_request_context() else 'en'
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
        with current_app.app_context():
            from flask_login import current_user
            from flask import request
            if user_id is None and current_user.is_authenticated:
                user_id = current_user.id
            session_id = session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'
            log_entry = {
                'user_id': user_id,
                'session_id': session_id,
                'action': action,
                'details': details or {},
                'timestamp': datetime.utcnow(),
                'ip_address': request.remote_addr if has_request_context() else None,
                'user_agent': request.headers.get('User-Agent') if has_request_context() else None
            }
            db = get_mongo_db()
            if db:
                db.audit_logs.insert_one(log_entry)
            logger.info(f"{trans('general_user_action_logged', default='User action logged')}: {action} by user {user_id}")
    except Exception as e:
        logger.error(f"{trans('general_user_action_log_error', default='Error logging user action')}: {str(e)}", exc_info=True)

def send_sms_reminder(recipient, message):
    """
    Send an SMS reminder to the specified recipient.
    
    Args:
        recipient: Phone number of the recipient
        message: Message to send
    
    Returns:
        tuple: (success, api_response)
    """
    try:
        with current_app.app_context():
            recipient = re.sub(r'\D', '', recipient)
            if recipient.startswith('0'):
                recipient = '234' + recipient[1:]
            elif not recipient.startswith('+'):
                recipient = '234' + recipient
            sms_api_url = current_app.config.get('SMS_API_URL', 'https://api.smsprovider.com/send')
            sms_api_key = current_app.config.get('SMS_API_KEY', '')
            if not sms_api_key:
                logger.warning('SMS_API_KEY not set, cannot send SMS')
                return False, {'error': 'SMS_API_KEY not configured'}
            payload = {
                'to': f'+{recipient}',
                'message': message,
                'api_key': sms_api_key
            }
            response = requests.post(sms_api_url, json=payload, timeout=10)
            response_data = response.json()
            if response.status_code == 200 and response_data.get('success', False):
                logger.info(f"SMS sent to {recipient}")
                return True, response_data
            else:
                logger.error(f"Failed to send SMS to {recipient}: {response_data}")
                return False, response_data
    except Exception as e:
        logger.error(f"Error sending SMS to {recipient}: {str(e)}", exc_info=True)
        return False, {'error': str(e)}

def send_whatsapp_reminder(recipient, message):
    """
    Send a WhatsApp reminder to the specified recipient.
    
    Args:
        recipient: Phone number of the recipient
        message: Message to send
    
    Returns:
        tuple: (success, api_response)
    """
    try:
        with current_app.app_context():
            recipient = re.sub(r'\D', '', recipient)
            if recipient.startswith('0'):
                recipient = '234' + recipient[1:]
            elif not recipient.startswith('+'):
                recipient = '234' + recipient
            whatsapp_api_url = current_app.config.get('WHATSAPP_API_URL', 'https://api.whatsapp.com/send')
            whatsapp_api_key = current_app.config.get('WHATSAPP_API_KEY', '')
            if not whatsapp_api_key:
                logger.warning('WHATSAPP_API_KEY not set, cannot send WhatsApp message')
                return False, {'error': 'WHATSAPP_API_KEY not configured'}
            payload = {
                'phone': f'+{recipient}',
                'text': message,
                'api_key': whatsapp_api_key
            }
            response = requests.post(whatsapp_api_url, json=payload, timeout=10)
            response_data = response.json()
            if response.status_code == 200 and response_data.get('success', False):
                logger.info(f"WhatsApp message sent to {recipient}")
                return True, response_data
            else:
                logger.error(f"Failed to send WhatsApp message to {recipient}: {response_data}")
                return False, response_data
    except Exception as e:
        logger.error(f"Error sending WhatsApp message to {recipient}: {str(e)}", exc_info=True)
        return False, {'error': str(e)}

def get_recent_activities(user_id=None, is_admin_user=False, db=None, session_id=None, limit=10):
    """
    Fetch recent activities across all tools for a user or session.
    
    Args:
        user_id: ID of the user (optional for admin)
        is_admin_user: Whether the user is an admin (default: False)
        db: MongoDB database instance (optional)
        session_id: Session ID for anonymous users (optional)
        limit: Maximum number of activities to return (default: 10)
    
    Returns:
        list: List of recent activity records
    """
    if db is None:
        db = get_mongo_db()
    
    query = {} if is_admin_user else {'user_id': str(user_id)} if user_id else {'session_id': session_id} if session_id else {}
    
    try:
        activities = []
        
        # Fetch recent bills
        bills = db.bills.find(query).sort('created_at', -1).limit(5)
        for bill in bills:
            if not bill.get('created_at') or not bill.get('bill_name'):
                logger.warning(f"Skipping invalid bill record: {bill.get('_id')}", extra={'session_id': session_id or 'unknown', 'ip': request.remote_addr or 'unknown'})
                continue
            activities.append({
                'type': 'bill',
                'description': trans('recent_activity_bill_added', default='Added bill: {name}', name=bill.get('bill_name', 'Unknown')),
                'timestamp': bill.get('created_at', datetime.utcnow()).isoformat(),
                'details': {
                    'amount': bill.get('amount', 0),
                    'due_date': bill.get('due_date', 'N/A'),
                    'status': bill.get('status', 'Unknown')
                },
                'icon': 'bi-receipt'
            })

        # Fetch recent budgets
        budgets = db.budgets.find(query).sort('created_at', -1).limit(5)
        for budget in budgets:
            activities.append({
                'type': 'budget',
                'description': trans('recent_activity_budget_created', default='Created budget with income: {amount}', amount=budget.get('income', 0)),
                'timestamp': budget.get('created_at', datetime.utcnow()).isoformat(),
                'details': {
                    'income': budget.get('income', 0),
                    'surplus_deficit': budget.get('surplus_deficit', 0)
                },
                'icon': 'bi-cash-coin'
            })

        # Fetch recent shopping lists
        shopping_lists = db.shopping_lists.find(query).sort('created_at', -1).limit(5)
        for list_item in shopping_lists:
            activities.append({
                'type': 'shopping_list',
                'description': trans('recent_activity_shopping_list_created', default='Created shopping list: {name}', name=list_item.get('name', 'Unknown')),
                'timestamp': list_item.get('created_at', datetime.utcnow()).isoformat(),
                'details': {
                    'budget': list_item.get('budget', 0),
                    'total_spent': list_item.get('total_spent', 0)
                },
                'icon': 'bi-cart'
            })

        # Fetch recent shopping items
        shopping_items = db.shopping_items.find(query).sort('created_at', -1).limit(5)
        for item in shopping_items:
            activities.append({
                'type': 'shopping_item',
                'description': trans('recent_activity_shopping_item_added', default='Added shopping item: {name}', name=item.get('name', 'Unknown')),
                'timestamp': item.get('created_at', datetime.utcnow()).isoformat(),
                'details': {
                    'quantity': item.get('quantity', 0),
                    'price': item.get('price', 0),
                    'status': item.get('status', 'to_buy')
                },
                'icon': 'bi-check-circle'
            })

        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        logger.debug(
            f"Fetched {len(activities)} recent activities for {'user ' + str(user_id) if user_id else 'session ' + str(session_id) if session_id else 'all'}",
            extra={'session_id': session_id or 'unknown', 'ip': request.remote_addr or 'unknown'}
        )
        
        return activities[:limit]
    except Exception as e:
        logger.error(
            f"Failed to fetch recent activities: {str(e)}",
            exc_info=True,
            extra={'session_id': session_id or 'unknown', 'ip': request.remote_addr or 'unknown'}
        )
        raise

def get_all_recent_activities(user_id=None, is_admin_user=False, db=None, session_id=None, limit=10):
    """
    Fetch recent activities across all tools for a user or session.
    
    Args:
        user_id: ID of the user (optional for admin)
        is_admin_user: Whether the user is an admin (default: False)
        db: MongoDB database instance (optional)
        session_id: Session ID for anonymous users (optional)
        limit: Maximum number of activities to return (default: 10)
    
    Returns:
        list: List of recent activity records
    """
    return get_recent_activities(user_id, is_admin_user, db, session_id, limit)

# Export all functions and variables
__all__ = [
    'login_manager', 'clean_currency', 'log_tool_usage', 'flask_session', 'csrf', 'babel', 'compress', 'limiter',
    'get_limiter', 'create_anonymous_session', 'trans_function', 'is_valid_email',
    'get_mongo_db', 'close_mongo_db', 'get_mail', 'requires_role', 'check_ficore_credit_balance',
    'get_user_query', 'is_admin', 'format_currency', 'format_date', 'sanitize_input',
    'generate_unique_id', 'validate_required_fields', 'get_user_language',
    'log_user_action', 'send_sms_reminder', 'send_whatsapp_reminder',
    'initialize_tools_with_urls',
    'PERSONAL_TOOLS', 'PERSONAL_NAV', 'PERSONAL_EXPLORE_FEATURES',
    'BUSINESS_TOOLS', 'BUSINESS_NAV', 'BUSINESS_EXPLORE_FEATURES',
    'AGENT_TOOLS', 'AGENT_NAV', 'AGENT_EXPLORE_FEATURES',
    'ADMIN_TOOLS', 'ADMIN_NAV', 'ADMIN_EXPLORE_FEATURES', 'ALL_TOOLS', 'get_explore_features',
    'get_recent_activities', 'get_all_recent_activities'
]
