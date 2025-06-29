from datetime import datetime
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError
from werkzeug.security import generate_password_hash
from bson import ObjectId
import os
import logging
import uuid
import time
from translations import trans

logger = logging.getLogger('ficore_app')

# Sample courses data
SAMPLE_COURSES = [
    {
        'id': 'budgeting_learning_101',
        'title_key': 'learning_hub_course_budgeting101_title',
        'title_en': 'Budgeting Learning 101',
        'title_ha': 'Tsarin Kudi 101',
        'description_en': 'Learn the basics of budgeting.',
        'description_ha': 'Koyon asalin tsarin kudi.',
        'is_premium': False
    },
    {
        'id': 'financial_quiz',
        'title_key': 'learning_hub_course_financial_quiz_title',
        'title_en': 'Financial Quiz',
        'title_ha': 'Jarabawar Kudi',
        'description_en': 'Test your financial knowledge.',
        'description_ha': 'Gwada ilimin ku na kudi.',
        'is_premium': False
    },
    {
        'id': 'savings_basics',
        'title_key': 'learning_hub_course_savings_basics_title',
        'title_en': 'Savings Basics',
        'title_ha': 'Asalin Tattara Kudi',
        'description_en': 'Understand how to save effectively.',
        'description_ha': 'Fahimci yadda ake tattara kudi yadda ya kamata.',
        'is_premium': False
    }
]

def get_db(mongo_uri=None):
    """
    Connects to the MongoDB database specified by mongo_uri.
    Returns the database object.
    """
    try:
        mongo_uri = mongo_uri or os.getenv('MONGO_URI', 'mongodb://localhost:27017/minirecords')
        client = MongoClient(mongo_uri, uuidRepresentation='standard')
        db_name = mongo_uri.split('/')[-1].split('?')[0] or 'minirecords'
        db = client[db_name]
        db.command('ping')
        logger.info(f"Successfully connected to MongoDB database: {db_name}")
        return db
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}")
        raise

def initialize_database(app):
    max_retries = 3
    retry_delay = 1
    mongo_client = MongoClient(os.getenv('MONGO_URI', 'mongodb://localhost:27017/minirecords'))
    
    for attempt in range(max_retries):
        try:
            mongo_client.admin.command('ping')
            logger.info(f"Attempt {attempt + 1}/{max_retries} - {trans('general_database_connection_established', default='MongoDB connection established')}")
            break
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"Failed to initialize database (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt == max_retries - 1:
                raise RuntimeError(trans('general_database_connection_failed', default='MongoDB connection failed after max retries'))
            time.sleep(retry_delay)
    
    try:
        db_instance = get_db()
        logger.info(f"MongoDB database: {db_instance.name}")
        collections = db_instance.list_collection_names()
        
        collection_schemas = {
            'users': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['_id', 'email', 'password', 'role'],
                        'properties': {
                            '_id': {'bsonType': 'string'},
                            'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                            'password': {'bsonType': 'string'},
                            'role': {'enum': ['personal', 'trader', 'agent', 'admin']},
                            'coin_balance': {'bsonType': 'int', 'minimum': 0},
                            'language': {'enum': ['en', 'ha']},
                            'created_at': {'bsonType': 'date'},
                            'display_name': {'bsonType': ['string', 'null']},
                            'is_admin': {'bsonType': 'bool'},
                            'setup_complete': {'bsonType': 'bool'},
                            'reset_token': {'bsonType': ['string', 'null']},
                            'reset_token_expiry': {'bsonType': ['date', 'null']},
                            'otp': {'bsonType': ['string', 'null']},
                            'otp_expiry': {'bsonType': ['date', 'null']},
                            'business_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'name': {'bsonType': 'string'},
                                    'address': {'bsonType': 'string'},
                                    'industry': {'bsonType': 'string'},
                                    'products_services': {'bsonType': 'string'},
                                    'phone_number': {'bsonType': 'string'}
                                }
                            },
                            'personal_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'first_name': {'bsonType': 'string'},
                                    'last_name': {'bsonType': 'string'},
                                    'phone_number': {'bsonType': 'string'},
                                    'address': {'bsonType': 'string'}
                                }
                            },
                            'agent_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'agent_name': {'bsonType': 'string'},
                                    'agent_id': {'bsonType': 'string'},
                                    'area': {'bsonType': 'string'},
                                    'role': {'bsonType': 'string'},
                                    'email': {'bsonType': 'string'},
                                    'phone': {'bsonType': 'string'}
                                }
                            }
                        }
                    }
                },
                'indexes': [
                    {'key': [('email', ASCENDING)], 'unique': True},
                    {'key': [('reset_token', ASCENDING)], 'sparse': True},
                    {'key': [('role', ASCENDING)]}
                ]
            },
            'records': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'type', 'name', 'amount_owed'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'type': {'enum': ['debtor', 'creditor']},
                            'name': {'bsonType': 'string'},
                            'contact': {'bsonType': ['string', 'null']},
                            'amount_owed': {'bsonType': 'number', 'minimum': 0},
                            'description': {'bsonType': ['string', 'null']},
                            'reminder_count': {'bsonType': 'int', 'minimum': 0},
                            'created_at': {'bsonType': 'date'},
                            'updated_at': {'bsonType': ['date', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING), ('type', ASCENDING)]},
                    {'key': [('created_at', DESCENDING)]}
                ]
            },
            'cashflows': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'type', 'party_name', 'amount'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'type': {'enum': ['receipt', 'payment']},
                            'party_name': {'bsonType': 'string'},
                            'amount': {'bsonType': 'number', 'minimum': 0},
                            'method': {'bsonType': ['string', 'null']},
                            'category': {'bsonType': ['string', 'null']},
                            'created_at': {'bsonType': 'date'},
                            'updated_at': {'bsonType': ['date', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING), ('type', ASCENDING)]},
                    {'key': [('created_at', DESCENDING)]}
                ]
            },
            'inventory': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'item_name', 'qty', 'unit', 'buying_price', 'selling_price'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'item_name': {'bsonType': 'string'},
                            'qty': {'bsonType': 'int', 'minimum': 0},
                            'unit': {'bsonType': 'string'},
                            'buying_price': {'bsonType': 'number', 'minimum': 0},
                            'selling_price': {'bsonType': 'number', 'minimum': 0},
                            'threshold': {'bsonType': 'int', 'minimum': 0},
                            'created_at': {'bsonType': 'date'},
                            'updated_at': {'bsonType': ['date', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('item_name', ASCENDING)]}
                ]
            },
            'coin_transactions': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'amount', 'type', 'date'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'amount': {'bsonType': 'int'},
                            'type': {'enum': ['credit', 'spend', 'purchase', 'admin_credit']},
                            'ref': {'bsonType': ['string', 'null']},
                            'date': {'bsonType': 'date'},
                            'facilitated_by_agent': {'bsonType': ['string', 'null']},
                            'payment_method': {'bsonType': ['string', 'null']},
                            'cash_amount': {'bsonType': ['number', 'null']},
                            'notes': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('date', DESCENDING)]}
                ]
            },
            'audit_logs': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['admin_id', 'action', 'timestamp'],
                        'properties': {
                            'admin_id': {'bsonType': 'string'},
                            'action': {'bsonType': 'string'},
                            'details': {'bsonType': ['object', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('admin_id', ASCENDING)]},
                    {'key': [('timestamp', DESCENDING)]}
                ]
            }
        }
        
        for collection_name, config in collection_schemas.items():
            if collection_name not in collections:
                db_instance.create_collection(collection_name, validator=config.get('validator', {}))
                logger.info(f"{trans('general_collection_created', default='Created collection')}: {collection_name}")
            
            existing_indexes = db_instance[collection_name].index_information()
            for index in config.get('indexes', []):
                keys = index['key']
                options = {k: v for k, v in index.items() if k != 'key'}
                index_key_tuple = tuple(keys)
                index_exists = False
                for existing_index_name, existing_index_info in existing_indexes.items():
                    if tuple(existing_index_info['key']) == index_key_tuple:
                        existing_options = {k: v for k, v in existing_index_info.items() if k not in ['key', 'v', 'ns']}
                        if existing_options == options:
                            logger.info(f"{trans('general_index_exists', default='Index already exists on')} {collection_name}: {keys} with options {options}")
                            index_exists = True
                        break
                if not index_exists:
                    db_instance[collection_name].create_index(keys, **options)
                    logger.info(f"{trans('general_index_created', default='Created index on')} {collection_name}: {keys} with options {options}")
        
        courses_collection = db_instance.courses
        if courses_collection.count_documents({}) == 0:
            for course in SAMPLE_COURSES:
                courses_collection.insert_one(course)
            logger.info(trans('general_courses_initialized', default='Initialized courses in MongoDB'))
        app.config['COURSES'] = list(courses_collection.find({}, {'_id': 0}))
        
        tax_rates_collection = db_instance.tax_rates
        if tax_rates_collection.count_documents({}) == 0:
            sample_rates = [
                {'role': 'personal', 'min_income': 0, 'max_income': 100000, 'rate': 0.1, 'description': trans('tax_rate_personal_description', default='10% tax for income up to 100,000')},
                {'role': 'trader', 'min_income': 0, 'max_income': 500000, 'rate': 0.15, 'description': trans('tax_rate_trader_description', default='15% tax for turnover up to 500,000')},
            ]
            tax_rates_collection.insert_many(sample_rates)
            logger.info(trans('general_tax_rates_initialized', default='Initialized tax rates in MongoDB'))
        
        payment_locations_collection = db_instance.payment_locations
        if payment_locations_collection.count_documents({}) == 0:
            sample_locations = [
                {'name': 'Gombe State IRS Office', 'address': '123 Tax Street, Gombe', 'contact': '+234 123 456 7890', 'coordinates': {'lat': 10.2896, 'lng': 11.1673}},
            ]
            payment_locations_collection.insert_many(sample_locations)
            logger.info(trans('general_payment_locations_initialized', default='Initialized payment locations in MongoDB'))
    
    except Exception as e:
        logger.error(f"{trans('general_database_initialization_failed', default='Failed to initialize database')}: {str(e)}", exc_info=True)
        raise

class User:
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

def create_user(db, user_data):
    try:
        user_id = user_data.get('username', user_data['email'].split('@')[0]).lower()
        if 'password' in user_data:
            user_data['password_hash'] = generate_password_hash(user_data['password'])
        
        user_doc = {
            '_id': user_id,
            'email': user_data['email'].lower(),
            'password': user_data['password_hash'],
            'role': user_data.get('role', 'personal'),
            'display_name': user_data.get('display_name', user_id),
            'is_admin': user_data.get('is_admin', False),
            'setup_complete': user_data.get('setup_complete', False),
            'coin_balance': user_data.get('coin_balance', 10),
            'language': user_data.get('lang', 'en'),
            'dark_mode': user_data.get('dark_mode', False),
            'created_at': user_data.get('created_at', datetime.utcnow()),
            'business_details': user_data.get('business_details'),
            'personal_details': user_data.get('personal_details'),
            'agent_details': user_data.get('agent_details')
        }
        
        db.users.insert_one(user_doc)
        logger.info(f"{trans('general_user_created', default='Created user with ID')}: {user_id}")
        
        return User(
            id=user_id,
            email=user_doc['email'],
            username=user_id,
            role=user_doc['role'],
            display_name=user_doc['display_name'],
            is_admin=user_doc['is_admin'],
            setup_complete=user_doc['setup_complete'],
            coin_balance=user_doc['coin_balance'],
            language=user_doc['language'],
            dark_mode=user_doc['dark_mode']
        )
    except DuplicateKeyError as e:
        logger.error(f"{trans('general_user_creation_error', default='Error creating user')}: {trans('general_duplicate_key_error', default='Duplicate key error')} - {str(e)}")
        raise ValueError(trans('general_user_exists', default='User with this email or username already exists'))
    except Exception as e:
        logger.error(f"{trans('general_user_creation_error', default='Error creating user')}: {str(e)}")
        raise

def get_user_by_email(db, email):
    try:
        user_doc = db.users.find_one({'email': email.lower()})
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
        logger.error(f"{trans('general_user_fetch_error', default='Error getting user by email')} {email}: {str(e)}")
        raise

def get_user(db, user_id):
    try:
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
        logger.error(f"{trans('general_user_fetch_error', default='Error getting user by ID')} {user_id}: {str(e)}")
        raise

def get_financial_health(db, filter_kwargs):
    try:
        return list(db.financial_health.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_financial_health_fetch_error', default='Error getting financial health')}: {str(e)}")
        raise

def get_budgets(db, filter_kwargs):
    try:
        return list(db.budgets.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_budgets_fetch_error', default='Error getting budgets')}: {str(e)}")
        raise

def get_bills(db, filter_kwargs):
    try:
        return list(db.bills.find(filter_kwargs).sort('due_date', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_bills_fetch_error', default='Error getting bills')}: {str(e)}")
        raise

def get_net_worth(db, filter_kwargs):
    try:
        return list(db.net_worth.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_net_worth_fetch_error', default='Error getting net worth')}: {str(e)}")
        raise

def get_emergency_funds(db, filter_kwargs):
    try:
        return list(db.emergency_funds.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_emergency_funds_fetch_error', default='Error getting emergency funds')}: {str(e)}")
        raise

def get_learning_progress(db, filter_kwargs):
    try:
        return list(db.learning_progress.find(filter_kwargs))
    except Exception as e:
        logger.error(f"{trans('general_learning_progress_fetch_error', default='Error getting learning progress')}: {str(e)}")
        raise

def get_quiz_results(db, filter_kwargs):
    try:
        return list(db.quiz_results.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_quiz_results_fetch_error', default='Error getting quiz results')}: {str(e)}")
        raise

def get_news_articles(db, filter_kwargs):
    try:
        return list(db.news_articles.find(filter_kwargs).sort('published_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_news_articles_fetch_error', default='Error getting news articles')}: {str(e)}")
        raise

def get_tax_rates(db, filter_kwargs):
    try:
        return list(db.tax_rates.find(filter_kwargs).sort('min_income', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_tax_rates_fetch_error', default='Error getting tax rates')}: {str(e)}")
        raise

def get_payment_locations(db, filter_kwargs):
    try:
        return list(db.payment_locations.find(filter_kwargs).sort('name', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_payment_locations_fetch_error', default='Error getting payment locations')}: {str(e)}")
        raise

def get_tax_reminders(db, filter_kwargs):
    try:
        return list(db.tax_reminders.find(filter_kwargs).sort('due_date', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_tax_reminders_fetch_error', default='Error getting tax reminders')}: {str(e)}")
        raise

def create_feedback(db, feedback_data):
    try:
        required_fields = ['user_id', 'tool_name', 'rating', 'timestamp']
        if not all(field in feedback_data for field in required_fields):
            raise ValueError(trans('general_missing_feedback_fields', default='Missing required feedback fields'))
        db.feedback.insert_one(feedback_data)
        logger.info(f"{trans('general_feedback_created', default='Created feedback record for tool')}: {feedback_data.get('tool_name')}")
    except Exception as e:
        logger.error(f"{trans('general_feedback_creation_error', default='Error creating feedback')}: {str(e)}")
        raise

def log_tool_usage(db, tool_name, user_id=None, session_id=None, action=None):
    try:
        usage_data = {
            'tool_name': tool_name,
            'user_id': user_id,
            'session_id': session_id,
            'action': action,
            'timestamp': datetime.utcnow()
        }
        db.tool_usage.insert_one(usage_data)
        logger.info(f"{trans('general_tool_usage_logged', default='Logged tool usage')}: {tool_name} - {action}")
    except Exception as e:
        logger.error(f"{trans('general_tool_usage_log_error', default='Error logging tool usage')}: {str(e)}")

def create_news_article(db, article_data):
    try:
        required_fields = ['title', 'content', 'source_type', 'published_at']
        if not all(field in article_data for field in required_fields):
            raise ValueError(trans('general_missing_news_fields', default='Missing required news article fields'))
        article_data.setdefault('is_verified', False)
        article_data.setdefault('is_active', True)
        result = db.news_articles.insert_one(article_data)
        logger.info(f"{trans('general_news_article_created', default='Created news article with ID')}: {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_news_article_creation_error', default='Error creating news article')}: {str(e)}")
        raise

def create_tax_rate(db, tax_rate_data):
    try:
        required_fields = ['role', 'min_income', 'max_income', 'rate', 'description']
        if not all(field in tax_rate_data for field in required_fields):
            raise ValueError(trans('general_missing_tax_rate_fields', default='Missing required tax rate fields'))
        result = db.tax_rates.insert_one(tax_rate_data)
        logger.info(f"{trans('general_tax_rate_created', default='Created tax rate with ID')}: {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_tax_rate_creation_error', default='Error creating tax rate')}: {str(e)}")
        raise

def create_payment_location(db, location_data):
    try:
        required_fields = ['name', 'address', 'contact']
        if not all(field in location_data for field in required_fields):
            raise ValueError(trans('general_missing_location_fields', default='Missing required payment location fields'))
        result = db.payment_locations.insert_one(location_data)
        logger.info(f"{trans('general_payment_location_created', default='Created payment location with ID')}: {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_payment_location_creation_error', default='Error creating payment location')}: {str(e)}")
        raise

def create_tax_reminder(db, reminder_data):
    try:
        required_fields = ['user_id', 'tax_type', 'due_date', 'amount', 'status', 'created_at']
        if not all(field in reminder_data for field in required_fields):
            raise ValueError(trans('general_missing_reminder_fields', default='Missing required tax reminder fields'))
        result = db.tax_reminders.insert_one(reminder_data)
        logger.info(f"{trans('general_tax_reminder_created', default='Created tax reminder with ID')}: {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_tax_reminder_creation_error', default='Error creating tax reminder')}: {str(e)}")
        raise
