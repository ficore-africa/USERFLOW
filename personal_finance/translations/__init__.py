import logging
from flask import session, has_request_context, g, request
from typing import Dict, Optional, Union
import threading

# Set up logger to match app.py
root_logger = logging.getLogger('ficore_app')
root_logger.setLevel(logging.DEBUG)

class SessionFormatter(logging.Formatter):
    def format(self, record):
        record.session_id = getattr(record, 'session_id', 'no_session_id')
        return super().format(record)

formatter = SessionFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s [session: %(session_id)s]')

class SessionAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        kwargs['extra'] = kwargs.get('extra', {})
        session_id = kwargs['extra'].get('session_id', 'no-session-id')
        if has_request_context():
            session_id = session.get('sid', 'no-session-id')
        kwargs['extra']['session_id'] = session_id
        return msg, kwargs

logger = SessionAdapter(root_logger, {})

# Thread-safe set to store logged missing keys
logged_missing_keys = set()
lock = threading.Lock()

# Import translation modules
try:
    # Personal Finance Tools
    from .personal_finance.bill_translations import BILL_TRANSLATIONS
    from .personal_finance.budget_translations import BUDGET_TRANSLATIONS
    from .personal_finance.shopping_translations import SHOPPING_TRANSLATIONS
    
    # General Tools
    from .general_tools.general_translations import GENERAL_TRANSLATIONS
    
except ImportError as e:
    logger.error(f"Failed to import translation module: {str(e)}", exc_info=True)
    raise

# Map module names to translation dictionaries
translation_modules = {
    # Personal Finance
    'bill': BILL_TRANSLATIONS,
    'budget': BUDGET_TRANSLATIONS,
    'shopping': SHOPPING_TRANSLATIONS,
    
    
    # General Tools
    'general': GENERAL_TRANSLATIONS,
}

# Map key prefixes to module names
KEY_PREFIX_TO_MODULE = {
    # Personal Finance prefixes
    'bill_': 'bill',
    'budget_': 'budget',
    'shopping_': 'shopping',
    
    # Accounting Tools prefixes
    'admin_': 'admin',
    'reports_': 'reports',
    
    # General Tools prefixes
    'general_': 'general',
    'notifications_': 'tax',
    'search_': 'tax',
    'filter_': 'tax',
    'export_': 'tax',
    'backup_': 'tax',
    'maintenance_': 'tax',
    'webhook_': 'tax',
}

# General-specific keys without prefixes (common navigation and UI elements)
GENERAL_SPECIFIC_KEYS = {
    'Home', 'About', 'Contact', 'Login', 'Logout', 'Register', 'Profile',
    'Settings', 'Help', 'Support', 'Terms', 'Privacy', 'FAQ', 'Documentation',
    'Get Started', 'Learn More', 'Try Now', 'Sign Up', 'Sign In', 'Welcome',
    'Dashboard', 'Tools', 'Features', 'Pricing', 'Blog', 'Updates',
    'Save', 'Cancel', 'Submit', 'Edit', 'Delete', 'Add', 'Create', 'Update',
    'View', 'Search', 'Filter', 'Sort', 'Export', 'Import', 'Print', 'Download',
    'Upload', 'Back', 'Next', 'Previous', 'Continue', 'Finish', 'Close', 'Open'
}

# Log loaded translations
for module_name, translations in translation_modules.items():
    for lang in ['en', 'ha']:
        lang_dict = translations.get(lang, {})
        logger.info(f"Loaded {len(lang_dict)} translations for module '{module_name}', lang='{lang}'")

def trans(key: str, lang: Optional[str] = None, default: Optional[str] = None, **kwargs: str) -> str:
    """
    Translate a key using the appropriate module's translation dictionary.
    
    Args:
        key: The translation key (e.g., 'bill_submit', 'general_welcome').
        lang: Language code ('en', 'ha'). Defaults to session['lang'] or 'en'.
        default: Default string to use if translation is missing. Defaults to None (returns key).
        **kwargs: String formatting parameters for the translated string.
    
    Returns:
        The translated string, falling back to English, default, or the key itself if missing.
        Applies string formatting with kwargs if provided, with fallback for missing keys.
    
    Notes:
        - Uses session['lang'] if lang is None and request context exists.
        - Logs warnings for missing translations only once per key.
        - Logs errors for formatting failures but returns unformatted string as fallback.
        - Uses g.logger if available, else the default logger.
        - Checks general translations for common UI elements without prefixes.
    """
    current_logger = g.get('logger', logger) if has_request_context() else logger
    session_id = session.get('sid', 'no-session-id') if has_request_context() else 'no-session-id'

    # Handle invalid translation keys (None or not a string)
    if key is None or not isinstance(key, str):
        with lock:
            error_key_id = f"invalid_key_{key}"
            if error_key_id not in logged_missing_keys:
                logged_missing_keys.add(error_key_id)
                current_logger.error(
                    f"Invalid translation key received: '{key}'. Must be a non-empty string.",
                    extra={'session_id': session_id}
                )
        return default or (str(key) if key is not None else '')

    # Default to session language or 'en'
    if lang is None:
        lang = session.get('lang', 'en') if has_request_context() else 'en'
    if lang not in ['en', 'ha']:
        with lock:
            if f"invalid_language_{lang}" not in logged_missing_keys:
                logged_missing_keys.add(f"invalid_language_{lang}")
                current_logger.warning(f"Invalid language '{lang}', falling back to 'en'", extra={'session_id': session_id})
        lang = 'en'

    # Determine module based on key prefix or specific keys
    module_name = 'general'  # Default to general
    
    # Check for specific prefix mappings
    for prefix, mod in KEY_PREFIX_TO_MODULE.items():
        if key.startswith(prefix):
            module_name = mod
            break
    
    # Check for general-specific keys (common UI elements)
    if key in GENERAL_SPECIFIC_KEYS:
        module_name = 'general'

    module = translation_modules.get(module_name, translation_modules['general'])
    lang_dict = module.get(lang, {})

    # Get translation
    translation = lang_dict.get(key)

    # Fallback to English, then default, then key
    if translation is None:
        en_dict = module.get('en', {})
        translation = en_dict.get(key, default or key)
        if translation == default or translation == key:
            with lock:
                if key not in logged_missing_keys:
                    logged_missing_keys.add(key)
                    current_logger.warning(
                        f"Missing translation for key='{key}' in module '{module_name}', lang='{lang}'",
                        extra={'session_id': session_id}
                    )

    # Apply string formatting with fallback for missing kwargs
    if kwargs:
        try:
            return translation.format(**kwargs)
        except KeyError as e:
            with lock:
                error_key = f"formatting_error_{key}_{lang}"
                if error_key not in logged_missing_keys:
                    logged_missing_keys.add(error_key)
                    current_logger.error(
                        f"Formatting error for key='{key}', lang='{lang}', kwargs={kwargs}, error='Missing key: {str(e)}'",
                        extra={'session_id': session_id}
                    )
            return translation  # Return unformatted string as fallback
        except ValueError as e:
            with lock:
                error_key = f"formatting_error_{key}_{lang}"
                if error_key not in logged_missing_keys:
                    logged_missing_keys.add(error_key)
                    current_logger.error(
                        f"Formatting failed for key='{key}', lang='{lang}', kwargs={kwargs}, error='Invalid format: {str(e)}'",
                        extra={'session_id': session_id}
                    )
            return translation  # Return unformatted string as fallback
    return translation

def get_translations(lang: Optional[str] = None) -> Dict[str, callable]:
    """
    Return a dictionary with a trans callable for the specified language.

    Args:
        lang: Language code ('en', 'ha'). Defaults to session['lang'] or 'en'.

    Returns:
        A dictionary with a 'trans' function that translates keys for the specified language.
    """
    if lang is None:
        lang = session.get('lang', 'en') if has_request_context() else 'en'
    if lang not in ['en', 'ha']:
        logger.warning(f"Invalid language '{lang}', falling back to 'en'", extra={'session_id': session.get('sid', 'no-session-id')})
        lang = 'en'
    return {
        'trans': lambda key, default=None, **kwargs: trans(key, lang=lang, default=default, **kwargs)
    }

def get_all_translations() -> Dict[str, Dict[str, Dict[str, str]]]:
    """
    Get all translations from all modules.
    
    Returns:
        A dictionary with module names as keys and their translation dictionaries as values.
    """
    return translation_modules.copy()

def get_module_translations(module_name: str, lang: Optional[str] = None) -> Dict[str, str]:
    """
    Get translations for a specific module and language.
    
    Args:
        module_name: Name of the translation module (e.g., 'general', 'bill').
        lang: Language code ('en', 'ha'). Defaults to session['lang'] or 'en'.
    
    Returns:
        Dictionary of translations for the specified module and language.
    """
    if lang is None:
        lang = session.get('lang', 'en') if has_request_context() else 'en'
    if lang not in ['en', 'ha']:
        logger.warning(f"Invalid language '{lang}', falling back to 'en'", extra={'session_id': session.get('sid', 'no-session-id')})
        lang = 'en'
    module = translation_modules.get(module_name, {})
    return module.get(lang, {})

def register_translation(app):
    """
    Register the translation function with Flask's Jinja2 environment.
    
    Args:
        app: Flask application instance.
    """
    app.jinja_env.globals['t'] = trans

    # Ensure session['lang'] is set before each request
    @app.before_request
    def set_default_language():
        if has_request_context() and 'lang' not in session:
            # Default to 'en' or use request headers/user settings as needed
            session['lang'] = request.accept_languages.best_match(['en', 'ha'], 'en')

__all__ = ['trans', 'get_translations', 'get_all_translations', 'get_module_translations', 'register_translation']
