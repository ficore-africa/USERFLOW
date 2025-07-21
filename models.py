from datetime import datetime
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError, OperationFailure
from werkzeug.security import generate_password_hash
from bson import ObjectId
import logging
from translations import trans
from utils import get_mongo_db, logger  # Use SessionAdapter logger from utils
from functools import lru_cache
import traceback
import time

# Configure logger for the application
logger = logging.getLogger('ficore_app')
logger.setLevel(logging.INFO)

def get_db():
    """
    Get MongoDB database connection using the global client from utils.py.
    
    Returns:
        Database object
    """
    try:
        db = get_mongo_db()
        logger.info(f"Successfully connected to MongoDB database: {db.name}", extra={'session_id': 'no-session-id'})
        return db
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}", exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def initialize_app_data(app):
    """
    Initialize MongoDB collections and indexes.
    
    Args:
        app: Flask application instance
    """
    max_retries = 3
    retry_delay = 1
    
    with app.app_context():
        for attempt in range(max_retries):
            try:
                db = get_db()
                db.command('ping')
                logger.info(f"Attempt {attempt + 1}/{max_retries} - {trans('general_database_connection_established', default='MongoDB connection established')}", 
                           extra={'session_id': 'no-session-id'})
                break
            except (ConnectionFailure, ServerSelectionTimeoutError) as e:
                logger.error(f"Failed to initialize database (attempt {attempt + 1}/{max_retries}): {str(e)}", 
                            exc_info=True, extra={'session_id': 'no-session-id'})
                if attempt == max_retries - 1:
                    raise RuntimeError(trans('general_database_connection_failed', default='MongoDB connection failed after max retries'))
                time.sleep(retry_delay)
        
        try:
            db_instance = get_db()
            logger.info(f"MongoDB database: {db_instance.name}", extra={'session_id': 'no-session-id'})
            collections = db_instance.list_collection_names()
            
            collection_schemas = {
                'users': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'email', 'password_hash', 'role'],
                            'properties': {
                                '_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'password_hash': {'bsonType': 'string'},
                                'role': {'enum': ['personal', 'trader', 'agent', 'admin']},
                                'coin_balance': {'bsonType': 'int', 'minimum': 0},
                                'ficore_credit_balance': {'bsonType': 'int', 'minimum': 0},
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
                'ficore_credit_transactions': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'amount', 'type', 'date'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'amount': {'bsonType': 'int'},
                                'type': {'enum': ['add', 'spend', 'purchase', 'admin_credit', 'create_grocery_list']},
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
                'credit_requests': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'amount', 'payment_method', 'status', 'created_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'amount': {'bsonType': 'int', 'minimum': 1},
                                'payment_method': {'enum': ['card', 'cash', 'bank']},
                                'receipt_file_id': {'bsonType': ['objectId', 'null']},
                                'status': {'enum': ['pending', 'approved', 'denied']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']},
                                'admin_id': {'bsonType': ['string', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        [{'key': [('user_id', ASCENDING)]},
                         {'key': [('status', ASCENDING)]},
                         {'key': [('created_at', DESCENDING)]}]
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
                },
                'agents': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'status', 'created_at'],
                            'properties': {
                                '_id': {'bsonType': 'string', 'pattern': r'^[A-Z0-9]{8}$'},
                                'status': {'enum': ['active', 'inactive']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('status', ASCENDING)]}
                    ]
                },
                'tax_rates': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['role', 'min_income', 'max_income', 'rate', 'description'],
                            'properties': {
                                'role': {'enum': ['personal', 'trader', 'agent', 'company']},
                                'min_income': {'bsonType': 'number'},
                                'max_income': {'bsonType': 'number'},
                                'rate': {'bsonType': 'number', 'minimum': 0, 'maximum': 1},
                                'description': {'bsonType': 'string'},
                                'session_id': {'bsonType': ['string', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('role', ASCENDING)]},
                        {'key': [('min_income', ASCENDING)]},
                        {'key': [('session_id', ASCENDING)]}
                    ]
                },
                'payment_locations': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['name', 'address', 'contact'],
                            'properties': {
                                'name': {'bsonType': 'string'},
                                'address': {'bsonType': 'string'},
                                'contact': {'bsonType': 'string'},
                                'coordinates': {
                                    'bsonType': ['object', 'null'],
                                    'properties': {
                                        'lat': {'bsonType': 'number'},
                                        'lng': {'bsonType': 'number'}
                                    }
                                }
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('name', ASCENDING)]}
                    ]
                },
                'tax_reminders': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'tax_type', 'due_date', 'amount', 'status', 'created_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'session_id': {'bsonType': ['string', 'null']},
                                'tax_type': {'bsonType': 'string'},
                                'due_date': {'bsonType': 'date'},
                                'amount': {'bsonType': 'number', 'minimum': 0},
                                'status': {'enum': ['pending', 'paid', 'overdue']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING)]},
                        {'key': [('session_id', ASCENDING)]},
                        {'key': [('due_date', ASCENDING)]}
                    ]
                },
                'vat_rules': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['category', 'vat_exempt', 'description'],
                            'properties': {
                                'category': {'bsonType': 'string'},
                                'vat_exempt': {'bsonType': 'bool'},
                                'description': {'bsonType': 'string'},
                                'session_id': {'bsonType': ['string', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('category', ASCENDING)], 'unique': True},
                        {'key': [('session_id', ASCENDING)]}
                    ]
                },
                'tax_deadlines': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['deadline_date', 'description', 'created_at'],
                            'properties': {
                            'description': {'bsonType': 'string'},
                            'created_at': {'bsonType': 'date'},
                            'session_id': {'bsonType': ['string', 'null']},
                            'user_id': {'bsonType': ['string', 'null']},
                            'list_id': {'bsonType': ['string', 'null']},
                            'updated_at': {'bsonType': ['date', 'null']}
                        }
                     }   
                    },
                    'indexes': [
                        {'key': [('deadline_date', ASCENDING)]},
                        {'key': [('user_id', ASCENDING), ('created_at', DESCENDING)]},
                        {'key': [('list_id', ASCENDING), ('created_at', DESCENDING)]},
                        {'key': [('updated_at', DESCENDING)]}
                    ]
                },
                'grocery_items': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'list_id', 'name', 'quantity', 'price', 'category', 'status', 'created_at', 'updated_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'list_id': {'bsonType': 'string'},
                                'name': {'bsonType': 'string'},
                                'quantity': {'bsonType': 'int', 'minimum': 1},
                                'price': {'bsonType': 'double', 'minimum': 0},
                                'category': {'enum': ['fruits', 'vegetables', 'dairy', 'meat', 'grains', 'beverages', 'household', 'other']},
                                'status': {'enum': ['to_buy', 'in_pantry', 'bought']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': 'date'},
                                'store': {'bsonType': ['string', 'null']},
                                'frequency': {'bsonType': 'int', 'minimum': 1}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('list_id', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
                    ]
                },
                'grocery_suggestions': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'list_id', 'name', 'quantity', 'price', 'category', 'status', 'created_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'list_id': {'bsonType': 'string'},
                                'name': {'bsonType': 'string'},
                                'quantity': {'bsonType': 'int', 'minimum': 1},
                                'price': {'bsonType': 'double', 'minimum': 0},
                                'category': {'enum': ['fruits', 'vegetables', 'dairy', 'meat', 'grains', 'beverages', 'household', 'other']},
                                'status': {'enum': ['pending', 'approved', 'rejected']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('list_id', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
                    ]
                },
                'meal_plans': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'name', 'ingredients', 'created_at', 'updated_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'name': {'bsonType': 'string'},
                                'ingredients': {
                                    'bsonType': 'array',
                                    'items': {
                                        'bsonType': 'object',
                                        'required': ['name', 'quantity', 'category', 'price'],
                                        'properties': {
                                            'name': {'bsonType': 'string'},
                                            'quantity': {'bsonType': 'int', 'minimum': 1},
                                            'category': {'enum': ['fruits', 'vegetables', 'dairy', 'meat', 'grains', 'beverages', 'household', 'other']},
                                            'price': {'bsonType': 'double', 'minimum': 0}
                                        }
                                    }
                                },
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
                    ]
                },
                'feedback': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'tool_name', 'rating', 'timestamp'],
                            'properties': {
                                'user_id': {'bsonType': ['string', 'null']},
                                'session_id': {'bsonType': ['string', 'null']},
                                'tool_name': {'bsonType': 'string'},
                                'rating': {'bsonType': 'int', 'minimum': 1, 'maximum': 5},
                                'comment': {'bsonType': ['string', 'null']},
                                'timestamp': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING)]},
                        {'key': [('session_id', ASCENDING)]},
                        {'key': [('timestamp', DESCENDING)]}
                    ]
                },
                'tool_usage': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['tool_name', 'timestamp'],
                            'properties': {
                                'tool_name': {'bsonType': 'string'},
                                'user_id': {'bsonType': ['string', 'null']},
                                'session_id': {'bsonType': ['string', 'null']},
                                'action': {'bsonType': ['string', 'null']},
                                'timestamp': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('tool_name', ASCENDING)]},
                        {'key': [('timestamp', DESCENDING)]}
                    ]
                },
                'budgets': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'income', 'fixed_expenses', 'variable_expenses', 'created_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'session_id': {'bsonType': ['string', 'null']},
                                'income': {'bsonType': 'number', 'minimum': 0},
                                'fixed_expenses': {'bsonType': 'number', 'minimum': 0},
                                'variable_expenses': {'bsonType': 'number', 'minimum': 0},
                                'savings_goal': {'bsonType': 'number', 'minimum': 0},
                                'surplus_deficit': {'bsonType': 'number'},
                                'housing': {'bsonType': 'number', 'minimum': 0},
                                'food': {'bsonType': 'number', 'minimum': 0},
                                'transport': {'bsonType': 'number', 'minimum': 0},
                                'dependents': {'bsonType': 'number', 'minimum': 0},
                                'miscellaneous': {'bsonType': 'number', 'minimum': 0},
                                'others': {'bsonType': 'number', 'minimum': 0},
                                'created_at': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('created_at', DESCENDING)]},
                        {'key': [('session_id', ASCENDING), ('created_at', DESCENDING)]}
                    ]
                },
                'bills': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'bill_name', 'amount', 'due_date', 'status'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'session_id': {'bsonType': ['string', 'null']},
                                'bill_name': {'bsonType': 'string'},
                                'amount': {'bsonType': 'number', 'minimum': 0},
                                'due_date': {'bsonType': 'date'},
                                'frequency': {'bsonType': ['string', 'null']},
                                'category': {'bsonType': ['string', 'null']},
                                'status': {'enum': ['pending', 'paid', 'overdue']},
                                'send_notifications': {'bsonType': 'bool'},
                                'send_email': {'bsonType': 'bool'},
                                'send_sms': {'bsonType': 'bool'},
                                'send_whatsapp': {'bsonType': 'bool'},
                                'reminder_days': {'bsonType': ['int', 'null']},
                                'user_email': {'bsonType': ['string', 'null']},
                                'user_phone': {'bsonType': ['string', 'null']},
                                'first_name': {'bsonType': ['string', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('due_date', ASCENDING)]},
                        {'key': [('session_id', ASCENDING), ('due_date', ASCENDING)]},
                        {'key': [('status', ASCENDING)]}
                    ]
                },
                'bill_reminders': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'notification_id', 'type', 'message', 'sent_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'session_id': {'bsonType': ['string', 'null']},
                                'notification_id': {'bsonType': 'string'},
                                'type': {'enum': ['email', 'sms', 'whatsapp']},
                                'message': {'bsonType': 'string'},
                                'sent_at': {'bsonType': 'date'},
                                'read_status': {'bsonType': 'bool'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('sent_at', DESCENDING)]},
                        {'key': [('session_id', ASCENDING), ('sent_at', DESCENDING)]}
                    ]
                },
                'sessions': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'data', 'expiration'],
                            'properties': {
                                '_id': {'bsonType': 'string'},
                                'data': {'bsonType': 'object'},
                                'expiration': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('expiration', ASCENDING)], 'expireAfterSeconds': 0}
                    ]
                }
            }
            
            for collection_name, config in collection_schemas.items():
                if collection_name == 'credit_requests' and collection_name in collections:
                    try:
                        db_instance.command('collMod', collection_name, validator=config.get('validator', {}))
                        logger.info(f"Updated validator for collection: {collection_name}", 
                                    extra={'session_id': 'no-session-id'})
                    except OperationFailure as e:
                        logger.error(f"Failed to update validator for collection {collection_name}: {str(e)}", 
                                    exc_info=True, extra={'session_id': 'no-session-id'})
                        raise
                elif collection_name not in collections:
                    try:
                        db_instance.create_collection(collection_name, validator=config.get('validator', {}))
                        logger.info(f"{trans('general_collection_created', default='Created collection')}: {collection_name}", 
                                   extra={'session_id': 'no-session-id'})
                    except OperationFailure as e:
                        logger.error(f"Failed to create collection {collection_name}: {str(e)}", 
                                    exc_info=True, extra={'session_id': 'no-session-id'})
                        raise
                
                existing_indexes = db_instance[collection_name].index_information()
                for index in config.get('indexes', []):
                    if isinstance(index, list):
                        for idx in index:
                            keys = idx['key']
                            options = {k: v for k, v in idx.items() if k != 'key'}
                            index_key_tuple = tuple(keys)
                            index_name = '_'.join(f"{k}_{v if isinstance(v, int) else str(v).replace(' ', '_')}" for k, v in keys)
                            index_exists = False
                            for existing_index_name, existing_index_info in existing_indexes.items():
                                if tuple(existing_index_info['key']) == index_key_tuple:
                                    existing_options = {k: v for k, v in existing_index_info.items() if k not in ['key', 'v', 'ns']}
                                    if existing_options == options:
                                        logger.info(f"{trans('general_index_exists', default='Index already exists on')} {collection_name}: {keys} with options {options}", 
                                                   extra={'session_id': 'no-session-id'})
                                        index_exists = True
                                    else:
                                        try:
                                            db_instance[collection_name].drop_index(existing_index_name)
                                            logger.info(f"Dropped conflicting index {existing_index_name} on {collection_name}", 
                                                       extra={'session_id': 'no-session-id'})
                                        except OperationFailure as e:
                                            logger.error(f"Failed to drop index {existing_index_name} on {collection_name}: {str(e)}", 
                                                        exc_info=True, extra={'session_id': 'no-session-id'})
                                            raise
                                    break
                            if not index_exists:
                                try:
                                    db_instance[collection_name].create_index(keys, name=index_name, **options)
                                    logger.info(f"{trans('general_index_created', default='Created index on')} {collection_name}: {keys} with options {options}", 
                                               extra={'session_id': 'no-session-id'})
                                except OperationFailure as e:
                                    if 'IndexKeySpecsConflict' in str(e):
                                        logger.info(f"Attempting to resolve index conflict for {collection_name}: {index_name}", 
                                                   extra={'session_id': 'no-session-id'})
                                        db_instance[collection_name].drop_index(index_name)
                                        db_instance[collection_name].create_index(keys, name=index_name, **options)
                                        logger.info(f"Recreated index on {collection_name}: {keys} with options {options}", 
                                                   extra={'session_id': 'no-session-id'})
                                    else:
                                        logger.error(f"Failed to create index on {collection_name}: {str(e)}", 
                                                    exc_info=True, extra={'session_id': 'no-session-id'})
                                        raise
                    else:
                        keys = index['key']
                        options = {k: v for k, v in index.items() if k != 'key'}
                        index_key_tuple = tuple(keys)
                        index_name = '_'.join(f"{k}_{v if isinstance(v, int) else str(v).replace(' ', '_')}" for k, v in keys)
                        index_exists = False
                        for existing_index_name, existing_index_info in existing_indexes.items():
                            if tuple(existing_index_info['key']) == index_key_tuple:
                                existing_options = {k: v for k, v in existing_index_info.items() if k not in ['key', 'v', 'ns']}
                                if existing_options == options:
                                    logger.info(f"{trans('general_index_exists', default='Index already exists on')} {collection_name}: {keys} with options {options}", 
                                               extra={'session_id': 'no-session-id'})
                                    index_exists = True
                                else:
                                    try:
                                        db_instance[collection_name].drop_index(existing_index_name)
                                        logger.info(f"Dropped conflicting index {existing_index_name} on {collection_name}", 
                                                   extra={'session_id': 'no-session-id'})
                                    except OperationFailure as e:
                                        logger.error(f"Failed to drop index {existing_index_name} on {collection_name}: {str(e)}", 
                                                    exc_info=True, extra={'session_id': 'no-session-id'})
                                        raise
                                break
                        if not index_exists:
                            try:
                                db_instance[collection_name].create_index(keys, name=index_name, **options)
                                logger.info(f"{trans('general_index_created', default='Created index on')} {collection_name}: {keys} with options {options}", 
                                           extra={'session_id': 'no-session-id'})
                            except OperationFailure as e:
                                if 'IndexKeySpecsConflict' in str(e):
                                    logger.info(f"Attempting to resolve index conflict for {collection_name}: {index_name}", 
                                               extra={'session_id': 'no-session-id'})
                                    db_instance[collection_name].drop_index(index_name)
                                    db_instance[collection_name].create_index(keys, name=index_name, **options)
                                    logger.info(f"Recreated index on {collection_name}: {keys} with options {options}", 
                                               extra={'session_id': 'no-session-id'})
                                else:
                                    logger.error(f"Failed to create index on {collection_name}: {str(e)}", 
                                                exc_info=True, extra={'session_id': 'no-session-id'})
                                    raise
            
            # Initialize agents
            agents_collection = db_instance.agents
            if agents_collection.count_documents({}) == 0:
                try:
                    agents_collection.insert_many([
                        {
                            '_id': 'AG123456',
                            'status': 'active',
                            'created_at': datetime.utcnow(),
                            'updated_at': datetime.utcnow()
                        }
                    ])
                    logger.info(trans('general_agents_initialized', default='Initialized agents in MongoDB'), 
                               extra={'session_id': 'no-session-id'})
                except OperationFailure as e:
                    logger.error(f"Failed to insert sample agents: {str(e)}", exc_info=True, extra={'session_id': 'no-session-id'})
                    raise
            
            # Initialize VAT rules
            vat_rules_collection = db_instance.vat_rules
            if vat_rules_collection.count_documents({}) == 0:
                try:
                    vat_rules_collection.insert_many([
                        {'category': 'food', 'vat_exempt': True, 'description': trans('tax_vat_exempt_food', default='Food items are VAT-exempt'), 'session_id': None},
                        {'category': 'healthcare', 'vat_exempt': True, 'description': trans('tax_vat_exempt_healthcare', default='Healthcare services are VAT-exempt'), 'session_id': None},
                        {'category': 'education', 'vat_exempt': True, 'description': trans('tax_vat_exempt_education', default='Educational services are VAT-exempt'), 'session_id': None},
                        {'category': 'rent', 'vat_exempt': True, 'description': trans('tax_vat_exempt_rent', default='Rent is VAT-exempt'), 'session_id': None},
                        {'category': 'power', 'vat_exempt': True, 'description': trans('tax_vat_exempt_power', default='Power supply is VAT-exempt'), 'session_id': None},
                        {'category': 'baby_products', 'vat_exempt': True, 'description': trans('tax_vat_exempt_baby_products', default='Baby products are VAT-exempt'), 'session_id': None},
                        {'category': 'other', 'vat_exempt': False, 'description': trans('tax_vat_default', default='Default 7.5% VAT applied'), 'session_id': None}
                    ])
                    logger.info(trans('general_vat_rules_initialized', default='Initialized VAT rules in MongoDB'), 
                                extra={'session_id': 'no-session-id'})
                except OperationFailure as e:
                    logger.error(f"Failed to insert VAT rules: {str(e)}", exc_info=True, extra={'session_id': 'no-session-id'})
                    raise
            
        except Exception as e:
            logger.error(f"{trans('general_database_initialization_failed', default='Failed to initialize database')}: {str(e)}", 
                        exc_info=True, extra={'session_id': 'no-session-id'})
            raise

class User:
    def __init__(self, id, email, display_name=None, role='personal', username=None, is_admin=False, setup_complete=False, coin_balance=0, ficore_credit_balance=0, language='en', dark_mode=False):
        self.id = id
        self.email = email
        self.username = username or display_name or email.split('@')[0]
        self.role = role
        self.display_name = display_name or self.username
        self.is_admin = is_admin
        self.setup_complete = setup_complete
        self.coin_balance = coin_balance
        self.ficore_credit_balance = ficore_credit_balance
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
    """
    Create a new user in the users collection.
    
    Args:
        db: MongoDB database instance
        user_data: Dictionary containing user information
    
    Returns:
        User: Created user object
    """
    try:
        user_id = user_data.get('username', user_data['email'].split('@')[0]).lower()
        if 'password' in user_data:
            user_data['password_hash'] = generate_password_hash(user_data['password'])
        
        user_doc = {
            '_id': user_id,
            'email': user_data['email'].lower(),
            'password_hash': user_data.get('password_hash'),
            'role': user_data.get('role', 'personal'),
            'display_name': user_data.get('display_name', user_id),
            'is_admin': user_data.get('is_admin', False),
            'setup_complete': user_data.get('setup_complete', False),
            'coin_balance': user_data.get('coin_balance', 10),
            'ficore_credit_balance': user_data.get('ficore_credit_balance', 0),
            'language': user_data.get('lang', 'en'),
            'dark_mode': user_data.get('dark_mode', False),
            'created_at': user_data.get('created_at', datetime.utcnow()),
            'business_details': user_data.get('business_details'),
            'personal_details': user_data.get('personal_details'),
            'agent_details': user_data.get('agent_details')
        }
        
        db.users.insert_one(user_doc)
        logger.info(f"{trans('general_user_created', default='Created user with ID')}: {user_id}", 
                   extra={'session_id': 'no-session-id'})
        get_user.cache_clear()
        get_user_by_email.cache_clear()
        return User(
            id=user_id,
            email=user_doc['email'],
            username=user_id,
            role=user_doc['role'],
            display_name=user_doc['display_name'],
            is_admin=user_doc['is_admin'],
            setup_complete=user_doc['setup_complete'],
            coin_balance=user_doc['coin_balance'],
            ficore_credit_balance=user_doc['ficore_credit_balance'],
            language=user_doc['language'],
            dark_mode=user_doc['dark_mode']
        )
    except DuplicateKeyError as e:
        logger.error(f"{trans('general_user_creation_error', default='Error creating user')}: {trans('general_duplicate_key_error', default='Duplicate key error')} - {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise ValueError(trans('general_user_exists', default='User with this email or username already exists'))
    except Exception as e:
        logger.error(f"{trans('general_user_creation_error', default='Error creating user')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

@lru_cache(maxsize=128)
def get_user_by_email(db, email):
    """
    Retrieve a user by email from the users collection.
    
    Args:
        db: MongoDB database instance
        email: Email address of the user
    
    Returns:
        User: User object or None if not found
    """
    try:
        logger.debug(f"Calling get_user_by_email for email: {email}, stack: {''.join(traceback.format_stack()[-5:])}", 
                    extra={'session_id': 'no-session-id'})
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
                ficore_credit_balance=user_doc.get('ficore_credit_balance', 0),
                language=user_doc.get('language', 'en'),
                dark_mode=user_doc.get('dark_mode', False)
            )
        return None
    except Exception as e:
        logger.error(f"{trans('general_user_fetch_error', default='Error getting user by email')} {email}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

@lru_cache(maxsize=128)
def get_user(db, user_id):
    """
    Retrieve a user by ID from the users collection.
    
    Args:
        db: MongoDB database instance
        user_id: ID of the user
    
    Returns:
        User: User object or None if not found
    """
    try:
        logger.debug(f"Calling get_user for user_id: {user_id}, stack: {''.join(traceback.format_stack()[-5:])}", 
                    extra={'session_id': 'no-session-id'})
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
                ficore_credit_balance=user_doc.get('ficore_credit_balance', 0),
                language=user_doc.get('language', 'en'),
                dark_mode=user_doc.get('dark_mode', False)
            )
        return None
    except Exception as e:
        logger.error(f"{trans('general_user_fetch_error', default='Error getting user by ID')} {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_credit_request(db, request_data):
    """
    Create a new credit request in the credit_requests collection.
    
    Args:
        db: MongoDB database instance
        request_data: Dictionary containing credit request information
    
    Returns:
        str: ID of the created credit request
    """
    try:
        required_fields = ['user_id', 'amount', 'payment_method', 'status', 'created_at']
        if not all(field in request_data for field in required_fields):
            raise ValueError(trans('credits_missing_request_fields', default='Missing required credit request fields'))
        result = db.credit_requests.insert_one(request_data)
        logger.info(f"{trans('credits_request_created', default='Created credit request with ID')}: {result.inserted_id}", 
                   extra={'session_id': request_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('credits_request_creation_error', default='Error creating credit request')}: {str(e)}", 
                    exc_info=True, extra={'session_id': request_data.get('session_id', 'no-session-id')})
        raise

def update_credit_request(db, request_id, update_data):
    """
    Update a credit request in the credit_requests collection.
    
    Args:
        db: MongoDB database instance
        request_id: The ID of the credit request to update
        update_data: Dictionary containing fields to update (e.g., status, admin_id)
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.credit_requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('credits_request_updated', default='Updated credit request with ID')}: {request_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('credits_request_no_change', default='No changes made to credit request with ID')}: {request_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('credits_request_update_error', default='Error updating credit request with ID')} {request_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_credit_requests(db, filter_kwargs):
    """
    Retrieve credit request records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of credit request records
    """
    try:
        return list(db.credit_requests.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('credits_requests_fetch_error', default='Error getting credit requests')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_credit_request(record):
    """Convert credit request record to dictionary."""
    if not record:
        return {'user_id': None, 'amount': None, 'status': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'amount': record.get('amount', 0),
        'payment_method': record.get('payment_method', ''),
        'receipt_file_id': str(record.get('receipt_file_id', '')) if record.get('receipt_file_id') else None,
        'status': record.get('status', ''),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at'),
        'admin_id': record.get('admin_id')
    }

def get_agent(db, agent_id):
    """
    Retrieve an agent by ID from the agents collection.
    
    Args:
        db: MongoDB database instance
        agent_id: The agent ID to retrieve
    
    Returns:
        dict: Agent document or None if not found
    """
    try:
        agent_doc = db.agents.find_one({'_id': agent_id.upper()})
        if agent_doc:
            return {
                '_id': agent_doc['_id'],
                'status': agent_doc['status'],
                'created_at': agent_doc['created_at'],
                'updated_at': agent_doc.get('updated_at')
            }
        return None
    except Exception as e:
        logger.error(f"{trans('agents_fetch_error', default='Error getting agent by ID')} {agent_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_agent(db, agent_id, status):
    """
    Update an agent's status in the agents collection.
    
    Args:
        db: MongoDB database instance
        agent_id: The agent ID to update
        status: The new status ('active' or 'inactive')
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.agents.update_one(
            {'_id': agent_id.upper()},
            {'$set': {'status': status, 'updated_at': datetime.utcnow()}}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('agents_status_updated', default='Updated agent status for ID')}: {agent_id} to {status}", 
                       extra={'session_id': 'no-session-id'})
            return True
        return False
    except Exception as e:
        logger.error(f"{trans('agents_update_error', default='Error updating agent status for ID')} {agent_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_budgets(db, filter_kwargs):
    """
    Retrieve budget records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of budget records
    """
    try:
        return list(db.budgets.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_budgets_fetch_error', default='Error getting budgets')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_bills(db, filter_kwargs):
    """
    Retrieve bill records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of bill records
    """
    try:
        return list(db.bills.find(filter_kwargs).sort('due_date', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_bills_fetch_error', default='Error getting bills')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_tax_rates(db, filter_kwargs):
    """
    Retrieve tax rate records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of tax rate records
    """
    try:
        return list(db.tax_rates.find(filter_kwargs).sort('min_income', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_tax_rates_fetch_error', default='Error getting tax rates')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_payment_locations(db, filter_kwargs):
    """
    Retrieve payment location records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of payment location records
    """
    try:
        return list(db.payment_locations.find(filter_kwargs).sort('name', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_payment_locations_fetch_error', default='Error getting payment locations')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_tax_reminders(db, filter_kwargs):
    """
    Retrieve tax reminder records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of tax reminder records
    """
    try:
        return list(db.tax_reminders.find(filter_kwargs).sort('due_date', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_tax_reminders_fetch_error', default='Error getting tax reminders')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_vat_rules(db, filter_kwargs):
    """
    Retrieve VAT rule records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of VAT rule records
    """
    try:
        return list(db.vat_rules.find(filter_kwargs).sort('category', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_vat_rules_fetch_error', default='Error getting VAT rules')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_tax_deadlines(db, filter_kwargs):
    """
    Retrieve tax deadline records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of tax deadline records
    """
    try:
        return list(db.tax_deadlines.find(filter_kwargs).sort('deadline_date', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_tax_deadlines_fetch_error', default='Error getting tax deadlines')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_feedback(db, feedback_data):
    """
    Create a new feedback record in the feedback collection.
    
    Args:
        db: MongoDB database instance
        feedback_data: Dictionary containing feedback information
    """
    try:
        required_fields = ['user_id', 'tool_name', 'rating', 'timestamp']
        if not all(field in feedback_data for field in required_fields):
            raise ValueError(trans('general_missing_feedback_fields', default='Missing required feedback fields'))
        db.feedback.insert_one(feedback_data)
        logger.info(f"{trans('general_feedback_created', default='Created feedback record for tool')}: {feedback_data.get('tool_name')}", 
                   extra={'session_id': feedback_data.get('session_id', 'no-session-id')})
    except Exception as e:
        logger.error(f"{trans('general_feedback_creation_error', default='Error creating feedback')}: {str(e)}", 
                    exc_info=True, extra={'session_id': feedback_data.get('session_id', 'no-session-id')})
        raise

def log_tool_usage(db, tool_name, user_id=None, session_id=None, action=None):
    """
    Log tool usage in the tool_usage collection.
    
    Args:
        db: MongoDB database instance
        tool_name: Name of the tool used
        user_id: ID of the user (optional)
        session_id: Session ID (optional)
        action: Action performed (optional)
    """
    try:
        usage_data = {
            'tool_name': tool_name,
            'user_id': user_id,
            'session_id': session_id,
            'action': action,
            'timestamp': datetime.utcnow()
        }
        db.tool_usage.insert_one(usage_data)
        logger.info(f"{trans('general_tool_usage_logged', default='Logged tool usage')}: {tool_name} - {action}", 
                   extra={'session_id': session_id or 'no-session-id'})
    except Exception as e:
        logger.error(f"{trans('general_tool_usage_log_error', default='Error logging tool usage')}: {str(e)}", 
                    exc_info=True, extra={'session_id': session_id or 'no-session-id'})
        raise

def create_tax_rate(db, tax_rate_data):
    """
    Create a new tax rate in the tax_rates collection.
    
    Args:
        db: MongoDB database instance
        tax_rate_data: Dictionary containing tax rate information
    
    Returns:
        str: ID of the created tax rate
    """
    try:
        required_fields = ['role', 'min_income', 'max_income', 'rate', 'description']
        if not all(field in tax_rate_data for field in required_fields):
            raise ValueError(trans('general_missing_tax_rate_fields', default='Missing required tax rate fields'))
        result = db.tax_rates.insert_one(tax_rate_data)
        logger.info(f"{trans('general_tax_rate_created', default='Created tax rate with ID')}: {result.inserted_id}", 
                   extra={'session_id': tax_rate_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_tax_rate_creation_error', default='Error creating tax rate')}: {str(e)}", 
                    exc_info=True, extra={'session_id': tax_rate_data.get('session_id', 'no-session-id')})
        raise

def create_vat_rule(db, vat_rule_data):
    """
    Create a new VAT rule in the vat_rules collection.
    
    Args:
        db: MongoDB database instance
        vat_rule_data: Dictionary containing VAT rule information (category, vat_exempt, description)
    
    Returns:
        str: ID of the created VAT rule
    """
    try:
        required_fields = ['category', 'vat_exempt', 'description']
        if not all(field in vat_rule_data for field in required_fields):
            raise ValueError(trans('general_missing_vat_rule_fields', default='Missing required VAT rule fields'))
        result = db.vat_rules.insert_one(vat_rule_data)
        logger.info(f"{trans('general_vat_rule_created', default='Created VAT rule with ID')}: {result.inserted_id}", 
                   extra={'session_id': vat_rule_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except DuplicateKeyError as e:
        logger.error(f"{trans('general_vat_rule_creation_error', default='Error creating VAT rule')}: {trans('general_duplicate_key_error', default='Duplicate category error')} - {str(e)}", 
                    exc_info=True, extra={'session_id': vat_rule_data.get('session_id', 'no-session-id')})
        raise ValueError(trans('general_vat_rule_exists', default='VAT rule with this category already exists'))
    except Exception as e:
        logger.error(f"{trans('general_vat_rule_creation_error', value='Error creating VAT rule')}: {str(e)}", 
                    exc_info=True, extra={'session_id': vat_rule_data.get('session_id', 'no-session-id')})
        raise

def create_payment_location(db, location_data):
    """
    Create a new payment location in the payment_locations collection.
    
    Args:
        db: MongoDB database instance
        location_data: Dictionary containing payment location information
    
    Returns:
        str: ID of the created payment location
    """
    try:
        required_fields = ['name', 'address', 'contact']
        if not all(field in location_data for field in required_fields):
            raise ValueError(trans('general_missing_location_fields', default='Missing required payment location fields'))
        result = db.payment_locations.insert_one(location_data)
        logger.info(f"{trans('general_payment_location_created', default='Created payment location with ID')}: {result.inserted_id}", 
                   extra={'session_id': 'no-session-id'})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_payment_location_creation_error', default='Error creating payment location')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_tax_reminder(db, reminder_data):
    """
    Create a new tax reminder in the tax_reminders collection.
    
    Args:
        db: MongoDB database instance
        reminder_data: Dictionary containing tax reminder information (message as tax_type, reminder_date as due_date)
    
    Returns:
        str: ID of the created tax reminder
    """
    try:
        required_fields = ['user_id', 'tax_type', 'due_date', 'amount', 'status', 'created_at']
        if not all(field in reminder_data for field in required_fields):
            # Map template fields to schema
            if 'message' in reminder_data:
                reminder_data['tax_type'] = reminder_data.pop('message')
            if 'reminder_date' in reminder_data:
                reminder_data['due_date'] = reminder_data.pop('reminder_date')
            if not all(field in reminder_data for field in required_fields):
                raise ValueError(trans('general_missing_reminder_fields', default='Missing required tax reminder fields'))
        result = db.tax_reminders.insert_one(reminder_data)
        logger.info(f"{trans('general_tax_reminder_created', default='Created tax reminder with ID')}: {result.inserted_id}", 
                   extra={'session_id': reminder_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_tax_reminder_creation_error', default='Error creating tax reminder')}: {str(e)}", 
                    exc_info=True, extra={'session_id': reminder_data.get('session_id', 'no-session-id')})
        raise

def create_tax_deadline(db, deadline_data):
    """
    Create a new tax deadline in the tax_deadlines collection.
    
    Args:
        db: MongoDB database instance
        deadline_data: Dictionary containing tax deadline information
    
    Returns:
        str: ID of the created tax deadline
    """
    try:
        required_fields = ['deadline_date', 'description', 'created_at']
        if not all(field in deadline_data for field in required_fields):
            raise ValueError(trans('general_missing_deadline_fields', default='Missing required tax deadline fields'))
        result = db.tax_deadlines.insert_one(deadline_data)
        logger.info(f"{trans('general_tax_deadline_created', default='Created tax deadline with ID')}: {result.inserted_id}", 
                   extra={'session_id': deadline_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_tax_deadline_creation_error', default='Error creating tax deadline')}: {str(e)}", 
                    exc_info=True, extra={'session_id': deadline_data.get('session_id', 'no-session-id')})
        raise

def update_tax_reminder(db, reminder_id, update_data):
    """
    Update a tax reminder in the tax_reminders collection.
    
    Args:
        db: MongoDB database instance
        reminder_id: The ID of the tax reminder to update
        update_data: Dictionary containing fields to update (e.g., status, amount, due_date)
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.tax_reminders.update_one(
            {'_id': ObjectId(reminder_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_tax_reminder_updated', default='Updated tax reminder with ID')}: {reminder_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_tax_reminder_no_change', default='No changes made to tax reminder with ID')}: {reminder_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_tax_reminder_update_error', default='Error updating tax reminder with ID')} {reminder_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_budget(db, budget_data):
    """
    Create a new budget record in the budgets collection.
    
    Args:
        db: MongoDB database instance
        budget_data: Dictionary containing budget information
    
    Returns:
        str: ID of the created budget record
    """
    try:
        required_fields = ['user_id', 'income', 'fixed_expenses', 'variable_expenses', 'created_at']
        if not all(field in budget_data for field in required_fields):
            raise ValueError(trans('general_missing_budget_fields', default='Missing required budget fields'))
        result = db.budgets.insert_one(budget_data)
        logger.info(f"{trans('general_budget_created', default='Created budget record with ID')}: {result.inserted_id}", 
                   extra={'session_id': budget_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_budget_creation_error', default='Error creating budget record')}: {str(e)}", 
                    exc_info=True, extra={'session_id': budget_data.get('session_id', 'no-session-id')})
        raise

def create_bill(db, bill_data):
    """
    Create a new bill record in the bills collection.
    
    Args:
        db: MongoDB database instance
        bill_data: Dictionary containing bill information
    
    Returns:
        str: ID of the created bill record
    """
    try:
        required_fields = ['user_id', 'bill_name', 'amount', 'due_date', 'status']
        if not all(field in bill_data for field in required_fields):
            raise ValueError(trans('general_missing_bill_fields', default='Missing required bill fields'))
        result = db.bills.insert_one(bill_data)
        logger.info(f"{trans('general_bill_created', default='Created bill record with ID')}: {result.inserted_id}", 
                   extra={'session_id': bill_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_bill_creation_error', default='Error creating bill record')}: {str(e)}", 
                    exc_info=True, extra={'session_id': bill_data.get('session_id', 'no-session-id')})
        raise

def create_bill_reminder(db, reminder_data):
    """
    Create a new bill reminder in the bill_reminders collection.
    
    Args:
        db: MongoDB database instance
        reminder_data: Dictionary containing bill reminder information
    
    Returns:
        str: ID of the created bill reminder
    """
    try:
        required_fields = ['user_id', 'notification_id', 'type', 'message', 'sent_at']
        if not all(field in reminder_data for field in required_fields):
            raise ValueError(trans('general_missing_bill_reminder_fields', default='Missing required bill reminder fields'))
        result = db.bill_reminders.insert_one(reminder_data)
        logger.info(f"{trans('general_bill_reminder_created', default='Created bill reminder with ID')}: {result.inserted_id}", 
                   extra={'session_id': reminder_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_bill_reminder_creation_error', default='Error creating bill reminder')}: {str(e)}", 
                    exc_info=True, extra={'session_id': reminder_data.get('session_id', 'no-session-id')})
        raise

def get_records(db, filter_kwargs):
    """
    Retrieve records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of records
    """
    try:
        return list(db.records.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_records_fetch_error', default='Error getting records')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_record(db, record_data):
    """
    Create a new record in the records collection.
    
    Args:
        db: MongoDB database instance
        record_data: Dictionary containing record information
    
    Returns:
        str: ID of the created record
    """
    try:
        required_fields = ['user_id', 'type', 'name', 'amount_owed']
        if not all(field in record_data for field in required_fields):
            raise ValueError(trans('general_missing_record_fields', default='Missing required record fields'))
        result = db.records.insert_one(record_data)
        logger.info(f"{trans('general_record_created', default='Created record with ID')}: {result.inserted_id}", 
                   extra={'session_id': record_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_record_creation_error', default='Error creating record')}: {str(e)}", 
                    exc_info=True, extra={'session_id': record_data.get('session_id', 'no-session-id')})
        raise

def get_cashflows(db, filter_kwargs):
    """
    Retrieve cashflow records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of cashflow records
    """
    try:
        return list(db.cashflows.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_cashflows_fetch_error', default='Error getting cashflows')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_cashflow(db, cashflow_data):
    """
    Create a new cashflow record in the cashflows collection.
    
    Args:
        db: MongoDB database instance
        cashflow_data: Dictionary containing cashflow information
    
    Returns:
        str: ID of the created cashflow record
    """
    try:
        required_fields = ['user_id', 'type', 'party_name', 'amount']
        if not all(field in cashflow_data for field in required_fields):
            raise ValueError(trans('general_missing_cashflow_fields', default='Missing required cashflow fields'))
        result = db.cashflows.insert_one(cashflow_data)
        logger.info(f"{trans('general_cashflow_created', default='Created cashflow record with ID')}: {result.inserted_id}", 
                   extra={'session_id': cashflow_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_cashflow_creation_error', default='Error creating cashflow record')}: {str(e)}", 
                    exc_info=True, extra={'session_id': cashflow_data.get('session_id', 'no-session-id')})
        raise

def get_ficore_credit_transactions(db, filter_kwargs):
    """
    Retrieve ficore credit transaction records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of ficore credit transaction records
    """
    try:
        return list(db.ficore_credit_transactions.find(filter_kwargs).sort('date', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('credits_transactions_fetch_error', default='Error getting ficore credit transactions')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_ficore_credit_transaction(db, transaction_data):
    """
    Create a new ficore credit transaction in the ficore_credit_transactions collection.
    
    Args:
        db: MongoDB database instance
        transaction_data: Dictionary containing transaction information
    
    Returns:
        str: ID of the created transaction
    """
    try:
        required_fields = ['user_id', 'amount', 'type', 'date']
        if not all(field in transaction_data for field in required_fields):
            raise ValueError(trans('credits_missing_transaction_fields', default='Missing required ficore credit transaction fields'))
        result = db.ficore_credit_transactions.insert_one(transaction_data)
        logger.info(f"{trans('credits_transaction_created', default='Created ficore credit transaction with ID')}: {result.inserted_id}", 
                   extra={'session_id': transaction_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('credits_transaction_creation_error', default='Error creating ficore credit transaction')}: {str(e)}", 
                    exc_info=True, extra={'session_id': transaction_data.get('session_id', 'no-session-id')})
        raise

def get_audit_logs(db, filter_kwargs):
    """
    Retrieve audit log records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of audit log records
    """
    try:
        return list(db.audit_logs.find(filter_kwargs).sort('timestamp', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_audit_logs_fetch_error', default='Error getting audit logs')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_audit_log(db, audit_data):
    """
    Create a new audit log in the audit_logs collection.
    
    Args:
        db: MongoDB database instance
        audit_data: Dictionary containing audit log information
    
    Returns:
        str: ID of the created audit log
    """
    try:
        required_fields = ['admin_id', 'action', 'timestamp']
        if not all(field in audit_data for field in required_fields):
            raise ValueError(trans('general_missing_audit_fields', default='Missing required audit log fields'))
        result = db.audit_logs.insert_one(audit_data)
        logger.info(f"{trans('general_audit_log_created', default='Created audit log with ID')}: {result.inserted_id}", 
                   extra={'session_id': audit_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_audit_log_creation_error', default='Error creating audit log')}: {str(e)}", 
                    exc_info=True, extra={'session_id': audit_data.get('session_id', 'no-session-id')})
        raise

def update_user(db, user_id, update_data):
    """
    Update a user in the users collection.
    
    Args:
        db: MongoDB database instance
        user_id: The ID of the user to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        if 'password' in update_data:
            update_data['password_hash'] = generate_password_hash(update_data.pop('password'))
        result = db.users.update_one(
            {'_id': user_id},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_user_updated', default='Updated user with ID')}: {user_id}", 
                       extra={'session_id': 'no-session-id'})
            get_user.cache_clear()
            get_user_by_email.cache_clear()
            return True
        logger.info(f"{trans('general_user_no_change', default='No changes made to user with ID')}: {user_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_user_update_error', default='Error updating user with ID')} {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_record(record):
    """Convert record to dictionary."""
    if not record:
        return {'name': None, 'amount_owed': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'type': record.get('type', ''),
        'name': record.get('name', ''),
        'contact': record.get('contact', ''),
        'amount_owed': record.get('amount_owed', 0),
        'description': record.get('description', ''),
        'reminder_count': record.get('reminder_count', 0),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at')
    }

def to_dict_cashflow(record):
    """Convert cashflow record to dictionary."""
    if not record:
        return {'party_name': None, 'amount': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'type': record.get('type', ''),
        'party_name': record.get('party_name', ''),
        'amount': record.get('amount', 0),
        'method': record.get('method', ''),
        'category': record.get('category', ''),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at')
    }

def to_dict_ficore_credit_transaction(record):
    """Convert ficore credit transaction record to dictionary."""
    if not record:
        return {'amount': None, 'type': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'amount': record.get('amount', 0),
        'type': record.get('type', ''),
        'ref': record.get('ref', ''),
        'date': record.get('date'),
        'facilitated_by_agent': record.get('facilitated_by_agent', ''),
        'payment_method': record.get('payment_method', ''),
        'cash_amount': record.get('cash_amount', 0),
        'notes': record.get('notes', '')
    }

def to_dict_audit_log(record):
    """Convert audit log record to dictionary."""
    if not record:
        return {'action': None, 'timestamp': None}
    return {
        'id': str(record.get('_id', '')),
        'admin_id': record.get('admin_id', ''),
        'action': record.get('action', ''),
        'details': record.get('details', {}),
        'timestamp': record.get('timestamp')
    }

def to_dict_user(user):
    """Convert user object to dictionary."""
    if not user:
        return {'id': None, 'email': None}
    return {
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'role': user.role,
        'display_name': user.display_name,
        'is_admin': user.is_admin,
        'setup_complete': user.setup_complete,
        'coin_balance': user.coin_balance,
        'ficore_credit_balance': user.ficore_credit_balance,
        'language': user.language,
        'dark_mode': user.dark_mode
    }

def to_dict_budget(record):
    """Convert budget record to dictionary."""
    if not record:
        return {'surplus_deficit': None, 'savings_goal': None}
    return {
        'id': str(record.get('_id', '')),
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
        return {'bill_name': None, 'amount': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'bill_name': record.get('bill_name', ''),
        'amount': record.get('amount', 0),
        'due_date': record.get('due_date'),
        'frequency': record.get('frequency', ''),
        'category': record.get('category', ''),
        'status': record.get('status', ''),
        'send_notifications': record.get('send_notifications', False),
        'send_email': record.get('send_email', False),
        'send_sms': record.get('send_sms', False),
        'send_whatsapp': record.get('send_whatsapp', False),
        'reminder_days': record.get('reminder_days', None),
        'user_email': record.get('user_email', ''),
        'user_phone': record.get('user_phone', ''),
        'first_name': record.get('first_name', '')
    }

def to_dict_bill_reminder(record):
    """Convert bill reminder record to dictionary."""
    if not record:
        return {'notification_id': None, 'type': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'notification_id': record.get('notification_id', ''),
        'type': record.get('type', ''),
        'message': record.get('message', ''),
        'sent_at': record.get('sent_at'),
        'read_status': record.get('read_status', False)
    }

def to_dict_tax_rate(record):
    """Convert tax rate record to dictionary."""
    if not record:
        return {'role': None, 'rate': None}
    return {
        'id': str(record.get('_id', '')),
        'role': record.get('role', ''),
        'min_income': record.get('min_income', 0),
        'max_income': record.get('max_income', 0),
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
        'coordinates': record.get('coordinates', {})
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
        'updated_at': record.get('updated_at')
    }

def to_dict_vat_rule(record):
    """Convert VAT rule record to dictionary."""
    if not record:
        return {'category': None, 'vat_exempt': None}
    return {
        'id': str(record.get('_id', '')),
        'category': record.get('category', ''),
        'vat_exempt': record.get('vat_exempt', False),
        'description': record.get('description', '')
    }

def to_dict_tax_deadline(record):
    """Convert tax deadline record to dictionary."""
    if not record:
        return {'deadline_date': None, 'description': None}
    return {
        'id': str(record.get('_id', '')),
        'deadline_date': record.get('deadline_date'),
        'description': record.get('description', ''),
        'created_at': record.get('created_at')
    }

def create_grocery_item(db, item_data):
    """
    Create a new grocery item in the grocery_items collection.
    
    Args:
        db: MongoDB database instance
        item_data: Dictionary containing grocery item information
    
    Returns:
        str: ID of the created grocery item
    """
    try:
        required_fields = ['user_id', 'list_id', 'name', 'quantity', 'price', 'category', 'status', 'created_at', 'updated_at']
        if not all(field in item_data for field in required_fields):
            raise ValueError(trans('general_missing_grocery_item_fields', default='Missing required grocery item fields'))
        result = db.grocery_items.insert_one(item_data)
        logger.info(f"{trans('general_grocery_item_created', default='Created grocery item with ID')}: {result.inserted_id}", 
                   extra={'session_id': item_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_grocery_item_creation_error', default='Error creating grocery item')}: {str(e)}", 
                    exc_info=True, extra={'session_id': item_data.get('session_id', 'no-session-id')})
        raise

def get_grocery_items(db, filter_kwargs):
    """
    Retrieve grocery item records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of grocery item records
    """
    try:
        return list(db.grocery_items.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_grocery_items_fetch_error', default='Error getting grocery items')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_grocery_item(record):
    """Convert grocery item record to dictionary."""
    if not record:
        return {'name': None, 'quantity': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'list_id': record.get('list_id', ''),
        'name': record.get('name', ''),
        'quantity': record.get('quantity', 0),
        'price': record.get('price', 0.0),
        'category': record.get('category', ''),
        'status': record.get('status', ''),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at'),
        'store': record.get('store', ''),
        'frequency': record.get('frequency', 1)
    }

def create_grocery_suggestion(db, suggestion_data):
    """
    Create a new grocery suggestion in the grocery_suggestions collection.
    
    Args:
        db: MongoDB database instance
        suggestion_data: Dictionary containing grocery suggestion information
    
    Returns:
        str: ID of the created grocery suggestion
    """
    try:
        required_fields = ['user_id', 'list_id', 'name', 'quantity', 'price', 'category', 'status', 'created_at']
        if not all(field in suggestion_data for field in required_fields):
            raise ValueError(trans('general_missing_grocery_suggestion_fields', default='Missing required grocery suggestion fields'))
        result = db.grocery_suggestions.insert_one(suggestion_data)
        logger.info(f"{trans('general_grocery_suggestion_created', default='Created grocery suggestion with ID')}: {result.inserted_id}", 
                   extra={'session_id': suggestion_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_grocery_suggestion_creation_error', default='Error creating grocery suggestion')}: {str(e)}", 
                    exc_info=True, extra={'session_id': suggestion_data.get('session_id', 'no-session-id')})
        raise

def get_grocery_suggestions(db, filter_kwargs):
    """
    Retrieve grocery suggestion records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of grocery suggestion records
    """
    try:
        return list(db.grocery_suggestions.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_grocery_suggestions_fetch_error', default='Error getting grocery suggestions')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_grocery_suggestion(record):
    """Convert grocery suggestion record to dictionary."""
    if not record:
        return {'name': None, 'quantity': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'list_id': record.get('list_id', ''),
        'name': record.get('name', ''),
        'quantity': record.get('quantity', 0),
        'price': record.get('price', 0.0),
        'category': record.get('category', ''),
        'status': record.get('status', ''),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at')
    }

def create_meal_plan(db, meal_plan_data):
    """
    Create a new meal plan in the meal_plans collection.
    
    Args:
        db: MongoDB database instance
        meal_plan_data: Dictionary containing meal plan information
    
    Returns:
        str: ID of the created meal plan
    """
    try:
        required_fields = ['user_id', 'name', 'ingredients', 'created_at', 'updated_at']
        if not all(field in meal_plan_data for field in required_fields):
            raise ValueError(trans('general_missing_meal_plan_fields', default='Missing required meal plan fields'))
        result = db.meal_plans.insert_one(meal_plan_data)
        logger.info(f"{trans('general_meal_plan_created', default='Created meal plan with ID')}: {result.inserted_id}", 
                   extra={'session_id': meal_plan_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_meal_plan_creation_error', default='Error creating meal plan')}: {str(e)}", 
                    exc_info=True, extra={'session_id': meal_plan_data.get('session_id', 'no-session-id')})
        raise

def get_meal_plans(db, filter_kwargs):
    """
    Retrieve meal plan records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of meal plan records
    """
    try:
        return list(db.meal_plans.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_meal_plans_fetch_error', default='Error getting meal plans')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_meal_plan(record):
    """Convert meal plan record to dictionary."""
    if not record:
        return {'name': None, 'ingredients': []}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'name': record.get('name', ''),
        'ingredients': record.get('ingredients', []),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at')
    }

def update_grocery_item(db, item_id, update_data):
    """
    Update a grocery item in the grocery_items collection.
    
    Args:
        db: MongoDB database instance
        item_id: The ID of the grocery item to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.grocery_items.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_grocery_item_updated', default='Updated grocery item with ID')}: {item_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_grocery_item_no_change', default='No changes made to grocery item with ID')}: {item_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_grocery_item_update_error', default='Error updating grocery item with ID')} {item_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_grocery_suggestion(db, suggestion_id, update_data):
    """
    Update a grocery suggestion in the grocery_suggestions collection.
    
    Args:
        db: MongoDB database instance
        suggestion_id: The ID of the grocery suggestion to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.grocery_suggestions.update_one(
            {'_id': ObjectId(suggestion_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_grocery_suggestion_updated', default='Updated grocery suggestion with ID')}: {suggestion_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_grocery_suggestion_no_change', default='No changes made to grocery suggestion with ID')}: {suggestion_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_grocery_suggestion_update_error', default='Error updating grocery suggestion with ID')} {suggestion_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_meal_plan(db, meal_plan_id, update_data):
    """
    Update a meal plan in the meal_plans collection.
    
    Args:
        db: MongoDB database instance
        meal_plan_id: The ID of the meal plan to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.meal_plans.update_one(
            {'_id': ObjectId(meal_plan_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_meal_plan_updated', default='Updated meal plan with ID')}: {meal_plan_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_meal_plan_no_change', default='No changes made to meal plan with ID')}: {meal_plan_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_meal_plan_update_error', default='Error updating meal plan with ID')} {meal_plan_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_record(db, record_id, update_data):
    """
    Update a record in the records collection.
    
    Args:
        db: MongoDB database instance
        record_id: The ID of the record to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.records.update_one(
            {'_id': ObjectId(record_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_record_updated', default='Updated record with ID')}: {record_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_record_no_change', default='No changes made to record with ID')}: {record_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_record_update_error', default='Error updating record with ID')} {record_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_cashflow(db, cashflow_id, update_data):
    """
    Update a cashflow record in the cashflows collection.
    
    Args:
        db: MongoDB database instance
        cashflow_id: The ID of the cashflow record to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.cashflows.update_one(
            {'_id': ObjectId(cashflow_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_cashflow_updated', default='Updated cashflow record with ID')}: {cashflow_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_cashflow_no_change', default='No changes made to cashflow record with ID')}: {cashflow_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_cashflow_update_error', default='Error updating cashflow record with ID')} {cashflow_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_ficore_credit_transaction(db, transaction_id, update_data):
    """
    Update a ficore credit transaction in the ficore_credit_transactions collection.
    
    Args:
        db: MongoDB database instance
        transaction_id: The ID of the transaction to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.ficore_credit_transactions.update_one(
            {'_id': ObjectId(transaction_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('credits_transaction_updated', default='Updated ficore credit transaction with ID')}: {transaction_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('credits_transaction_no_change', default='No changes made to ficore credit transaction with ID')}: {transaction_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('credits_transaction_update_error', default='Error updating ficore credit transaction with ID')} {transaction_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_budget(db, budget_id, update_data):
    """
    Update a budget record in the budgets collection.
    
    Args:
        db: MongoDB database instance
        budget_id: The ID of the budget record to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.budgets.update_one(
            {'_id': ObjectId(budget_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_budget_updated', default='Updated budget record with ID')}: {budget_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_budget_no_change', default='No changes made to budget record with ID')}: {budget_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_budget_update_error', default='Error updating budget record with ID')} {budget_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_bill(db, bill_id, update_data):
    """
    Update a bill record in the bills collection.
    
    Args:
        db: MongoDB database instance
        bill_id: The ID of the bill record to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.bills.update_one(
            {'_id': ObjectId(bill_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_bill_updated', default='Updated bill record with ID')}: {bill_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_bill_no_change', default='No changes made to bill record with ID')}: {bill_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_bill_update_error', default='Error updating bill record with ID')} {bill_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_bill_reminder(db, reminder_id, update_data):
    """
    Update a bill reminder in the bill_reminders collection.
    
    Args:
        db: MongoDB database instance
        reminder_id: The ID of the bill reminder to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.bill_reminders.update_one(
            {'_id': ObjectId(reminder_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_bill_reminder_updated', default='Updated bill reminder with ID')}: {reminder_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_bill_reminder_no_change', default='No changes made to bill reminder with ID')}: {reminder_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_bill_reminder_update_error', default='Error updating bill reminder with ID')} {reminder_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_tax_rate(db, tax_rate_id, update_data):
    """
    Update a tax rate in the tax_rates collection.
    
    Args:
        db: MongoDB database instance
        tax_rate_id: The ID of the tax rate to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.tax_rates.update_one(
            {'_id': ObjectId(tax_rate_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_tax_rate_updated', default='Updated tax rate with ID')}: {tax_rate_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_tax_rate_no_change', default='No changes made to tax rate with ID')}: {tax_rate_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_tax_rate_update_error', default='Error updating tax rate with ID')} {tax_rate_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_vat_rule(db, vat_rule_id, update_data):
    """
    Update a VAT rule in the vat_rules collection.
    
    Args:
        db: MongoDB database instance
        vat_rule_id: The ID of the VAT rule to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.vat_rules.update_one(
            {'_id': ObjectId(vat_rule_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_vat_rule_updated', default='Updated VAT rule with ID')}: {vat_rule_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_vat_rule_no_change', default='No changes made to VAT rule with ID')}: {vat_rule_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_vat_rule_update_error', default='Error updating VAT rule with ID')} {vat_rule_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_payment_location(db, location_id, update_data):
    """
    Update a payment location in the payment_locations collection.
    
    Args:
        db: MongoDB database instance
        location_id: The ID of the payment location to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.payment_locations.update_one(
            {'_id': ObjectId(location_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_payment_location_updated', default='Updated payment location with ID')}: {location_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_payment_location_no_change', default='No changes made to payment location with ID')}: {location_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_payment_location_update_error', default='Error updating payment location with ID')} {location_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_tax_deadline(db, deadline_id, update_data):
    """
    Update a tax deadline in the tax_deadlines collection.
    
    Args:
        db: MongoDB database instance
        deadline_id: The ID of the tax deadline to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.tax_deadlines.update_one(
            {'_id': ObjectId(deadline_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_tax_deadline_updated', default='Updated tax deadline with ID')}: {deadline_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_tax_deadline_no_change', default='No changes made to tax deadline with ID')}: {deadline_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_tax_deadline_update_error', default='Error updating tax deadline with ID')} {deadline_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_grocery_item(db, item_id):
    """
    Delete a grocery item from the grocery_items collection.
    
    Args:
        db: MongoDB database instance
        item_id: The ID of the grocery item to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.grocery_items.delete_one({'_id': ObjectId(item_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_grocery_item_deleted', default='Deleted grocery item with ID')}: {item_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_grocery_item_not_found', default='Grocery item not found with ID')}: {item_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_grocery_item_delete_error', default='Error deleting grocery item with ID')} {item_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_grocery_suggestion(db, suggestion_id):
    """
    Delete a grocery suggestion from the grocery_suggestions collection.
    
    Args:
        db: MongoDB database instance
        suggestion_id: The ID of the grocery suggestion to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.grocery_suggestions.delete_one({'_id': ObjectId(suggestion_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_grocery_suggestion_deleted', default='Deleted grocery suggestion with ID')}: {suggestion_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_grocery_suggestion_not_found', default='Grocery suggestion not found with ID')}: {suggestion_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_grocery_suggestion_delete_error', default='Error deleting grocery suggestion with ID')} {suggestion_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_meal_plan(db, meal_plan_id):
    """
    Delete a meal plan from the meal_plans collection.
    
    Args:
        db: MongoDB database instance
        meal_plan_id: The ID of the meal plan to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.meal_plans.delete_one({'_id': ObjectId(meal_plan_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_meal_plan_deleted', default='Deleted meal plan with ID')}: {meal_plan_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_meal_plan_not_found', default='Meal plan not found with ID')}: {meal_plan_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_meal_plan_delete_error', default='Error deleting meal plan with ID')} {meal_plan_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_record(db, record_id):
    """
    Delete a record from the records collection.
    
    Args:
        db: MongoDB database instance
        record_id: The ID of the record to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.records.delete_one({'_id': ObjectId(record_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_record_deleted', default='Deleted record with ID')}: {record_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_record_not_found', default='Record not found with ID')}: {record_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_record_delete_error', default='Error deleting record with ID')} {record_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_cashflow(db, cashflow_id):
    """
    Delete a cashflow record from the cashflows collection.
    
    Args:
        db: MongoDB database instance
        cashflow_id: The ID of the cashflow record to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.cashflows.delete_one({'_id': ObjectId(cashflow_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_cashflow_deleted', default='Deleted cashflow record with ID')}: {cashflow_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_cashflow_not_found', default='Cashflow record not found with ID')}: {cashflow_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_cashflow_delete_error', default='Error deleting cashflow record with ID')} {cashflow_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_ficore_credit_transaction(db, transaction_id):
    """
    Delete a ficore credit transaction from the ficore_credit_transactions collection.
    
    Args:
        db: MongoDB database instance
        transaction_id: The ID of the transaction to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.ficore_credit_transactions.delete_one({'_id': ObjectId(transaction_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('credits_transaction_deleted', default='Deleted ficore credit transaction with ID')}: {transaction_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('credits_transaction_not_found', default='Ficore credit transaction not found with ID')}: {transaction_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('credits_transaction_delete_error', default='Error deleting ficore credit transaction with ID')} {transaction_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_credit_request(db, request_id):
    """
    Delete a credit request from the credit_requests collection.
    
    Args:
        db: MongoDB database instance
        request_id: The ID of the credit request to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.credit_requests.delete_one({'_id': ObjectId(request_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('credits_request_deleted', default='Deleted credit request with ID')}: {request_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('credits_request_not_found', default='Credit request not found with ID')}: {request_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('credits_request_delete_error', default='Error deleting credit request with ID')} {request_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_audit_log(db, audit_id):
    """
    Delete an audit log from the audit_logs collection.
    
    Args:
        db: MongoDB database instance
        audit_id: The ID of the audit log to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.audit_logs.delete_one({'_id': ObjectId(audit_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_audit_log_deleted', default='Deleted audit log with ID')}: {audit_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_audit_log_not_found', default='Audit log not found with ID')}: {audit_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_audit_log_delete_error', default='Error deleting audit log with ID')} {audit_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_user(db, user_id):
    """
    Delete a user from the users collection.
    
    Args:
        db: MongoDB database instance
        user_id: The ID of the user to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.users.delete_one({'_id': user_id})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_user_deleted', default='Deleted user with ID')}: {user_id}", 
                       extra={'session_id': 'no-session-id'})
            get_user.cache_clear()
            get_user_by_email.cache_clear()
            return True
        logger.info(f"{trans('general_user_not_found', default='User not found with ID')}: {user_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_user_delete_error', default='Error deleting user with ID')} {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_budget(db, budget_id):
    """
    Delete a budget record from the budgets collection.
    
    Args:
        db: MongoDB database instance
        budget_id: The ID of the budget record to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.budgets.delete_one({'_id': ObjectId(budget_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_budget_deleted', default='Deleted budget record with ID')}: {budget_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_budget_not_found', default='Budget record not found with ID')}: {budget_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_budget_delete_error', default='Error deleting budget record with ID')} {budget_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_bill(db, bill_id):
    """
    Delete a bill record from the bills collection.
    
    Args:
        db: MongoDB database instance
        bill_id: The ID of the bill record to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.bills.delete_one({'_id': ObjectId(bill_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_bill_deleted', default='Deleted bill record with ID')}: {bill_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_bill_not_found', default='Bill record not found with ID')}: {bill_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_bill_delete_error', default='Error deleting bill record with ID')} {bill_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_bill_reminder(db, reminder_id):
    """
    Delete a bill reminder from the bill_reminders collection.
    
    Args:
        db: MongoDB database instance
        reminder_id: The ID of the bill reminder to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.bill_reminders.delete_one({'_id': ObjectId(reminder_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_bill_reminder_deleted', default='Deleted bill reminder with ID')}: {reminder_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_bill_reminder_not_found', default='Bill reminder not found with ID')}: {reminder_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_bill_reminder_delete_error', default='Error deleting bill reminder with ID')} {reminder_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_tax_rate(db, tax_rate_id):
    """
    Delete a tax rate from the tax_rates collection.
    
    Args:
        db: MongoDB database instance
        tax_rate_id: The ID of the tax rate to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.tax_rates.delete_one({'_id': ObjectId(tax_rate_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_tax_rate_deleted', default='Deleted tax rate with ID')}: {tax_rate_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_tax_rate_not_found', default='Tax rate not found with ID')}: {tax_rate_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_tax_rate_delete_error', default='Error deleting tax rate with ID')} {tax_rate_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_vat_rule(db, vat_rule_id):
    """
    Delete a VAT rule from the vat_rules collection.
    
    Args:
        db: MongoDB database instance
        vat_rule_id: The ID of the VAT rule to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.vat_rules.delete_one({'_id': ObjectId(vat_rule_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_vat_rule_deleted', default='Deleted VAT rule with ID')}: {vat_rule_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_vat_rule_not_found', default='VAT rule not found with ID')}: {vat_rule_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_vat_rule_delete_error', default='Error deleting VAT rule with ID')} {vat_rule_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_payment_location(db, location_id):
    """
    Delete a payment location from the payment_locations collection.
    
    Args:
        db: MongoDB database instance
        location_id: The ID of the payment location to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.payment_locations.delete_one({'_id': ObjectId(location_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_payment_location_deleted', default='Deleted payment location with ID')}: {location_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_payment_location_not_found', default='Payment location not found with ID')}: {location_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_payment_location_delete_error', default='Error deleting payment location with ID')} {location_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_tax_reminder(db, reminder_id):
    """
    Delete a tax reminder from the tax_reminders collection.
    
    Args:
        db: MongoDB database instance
        reminder_id: The ID of the tax reminder to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.tax_reminders.delete_one({'_id': ObjectId(reminder_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_tax_reminder_deleted', default='Deleted tax reminder with ID')}: {reminder_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_tax_reminder_not_found', default='Tax reminder not found with ID')}: {reminder_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_tax_reminder_delete_error', default='Error deleting tax reminder with ID')} {reminder_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_tax_deadline(db, deadline_id):
    """
    Delete a tax deadline from the tax_deadlines collection.
    
    Args:
        db: MongoDB database instance
        deadline_id: The ID of the tax deadline to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.tax_deadlines.delete_one({'_id': ObjectId(deadline_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_tax_deadline_deleted', default='Deleted tax deadline with ID')}: {deadline_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_tax_deadline_not_found', default='Tax deadline not found with ID')}: {deadline_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_tax_deadline_delete_error', default='Error deleting tax deadline with ID')} {deadline_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise
