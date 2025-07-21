import logging
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError, PyMongoError
from bson import ObjectId
import uuid
from typing import Dict, List, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def trans(key, default=None, **kwargs):
    """Simple translation function - returns default for now"""
    return default or key

def initialize_app_data(db):
    """Initialize application data including collections, schemas, and indexes."""
    
    collection_schemas = {
        'users': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'username', 'email', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'username': {'bsonType': 'string'},
                        'email': {'bsonType': 'string'},
                        'password_hash': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'},
                        'is_active': {'bsonType': 'bool'},
                        'profile': {
                            'bsonType': 'object',
                            'properties': {
                                'first_name': {'bsonType': 'string'},
                                'last_name': {'bsonType': 'string'},
                                'phone': {'bsonType': 'string'}
                            }
                        }
                    }
                }
            },
            'indexes': [
                {'key': [('username', ASCENDING)], 'unique': True},
                {'key': [('email', ASCENDING)], 'unique': True}
            ]
        },
        'records': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'type', 'amount', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'type': {'bsonType': 'string'},
                        'amount': {'bsonType': 'double'},
                        'description': {'bsonType': 'string'},
                        'category': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('created_at', DESCENDING)]},
                {'key': [('type', ASCENDING)]}
            ]
        },
        'cashflows': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'amount', 'type', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'amount': {'bsonType': 'double'},
                        'type': {'bsonType': 'string'},
                        'description': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('created_at', DESCENDING)]},
                {'key': [('type', ASCENDING)]}
            ]
        },
        'ficore_credit_transactions': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'transaction_id', 'amount', 'status', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'transaction_id': {'bsonType': 'string'},
                        'amount': {'bsonType': 'double'},
                        'status': {'bsonType': 'string'},
                        'description': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('transaction_id', ASCENDING)], 'unique': True},
                {'key': [('status', ASCENDING)]},
                {'key': [('created_at', DESCENDING)]}
            ]
        },
        'credit_requests': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'amount', 'status', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'amount': {'bsonType': 'double'},
                        'status': {'bsonType': 'string'},
                        'reason': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'},
                        'processed_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('status', ASCENDING)]},
                {'key': [('created_at', DESCENDING)]}
            ]
        },
        'audit_logs': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'action', 'timestamp'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'action': {'bsonType': 'string'},
                        'details': {'bsonType': 'object'},
                        'timestamp': {'bsonType': 'date'},
                        'ip_address': {'bsonType': 'string'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('timestamp', DESCENDING)]},
                {'key': [('action', ASCENDING)]}
            ]
        },
        'agents': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'name', 'type', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'name': {'bsonType': 'string'},
                        'type': {'bsonType': 'string'},
                        'description': {'bsonType': 'string'},
                        'config': {'bsonType': 'object'},
                        'is_active': {'bsonType': 'bool'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('name', ASCENDING)], 'unique': True},
                {'key': [('type', ASCENDING)]},
                {'key': [('is_active', ASCENDING)]}
            ]
        },
        'tax_rates': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'country', 'rate', 'effective_date'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'country': {'bsonType': 'string'},
                        'state': {'bsonType': 'string'},
                        'rate': {'bsonType': 'double'},
                        'type': {'bsonType': 'string'},
                        'effective_date': {'bsonType': 'date'},
                        'end_date': {'bsonType': 'date'},
                        'created_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('country', ASCENDING)]},
                {'key': [('effective_date', DESCENDING)]},
                {'key': [('type', ASCENDING)]}
            ]
        },
        'payment_locations': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'name', 'address', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'name': {'bsonType': 'string'},
                        'address': {'bsonType': 'string'},
                        'city': {'bsonType': 'string'},
                        'country': {'bsonType': 'string'},
                        'coordinates': {
                            'bsonType': 'object',
                            'properties': {
                                'lat': {'bsonType': 'double'},
                                'lng': {'bsonType': 'double'}
                            }
                        },
                        'is_active': {'bsonType': 'bool'},
                        'created_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('name', ASCENDING)]},
                {'key': [('city', ASCENDING)]},
                {'key': [('is_active', ASCENDING)]}
            ]
        },
        'tax_reminders': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'title', 'due_date', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'title': {'bsonType': 'string'},
                        'description': {'bsonType': 'string'},
                        'due_date': {'bsonType': 'date'},
                        'is_completed': {'bsonType': 'bool'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('due_date', ASCENDING)]},
                {'key': [('is_completed', ASCENDING)]}
            ]
        },
        'vat_rules': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'country', 'rule_type', 'rate', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'country': {'bsonType': 'string'},
                        'rule_type': {'bsonType': 'string'},
                        'rate': {'bsonType': 'double'},
                        'description': {'bsonType': 'string'},
                        'effective_date': {'bsonType': 'date'},
                        'created_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('country', ASCENDING)]},
                {'key': [('rule_type', ASCENDING)]},
                {'key': [('effective_date', DESCENDING)]}
            ]
        },
        'tax_deadlines': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'country', 'tax_type', 'deadline', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'country': {'bsonType': 'string'},
                        'tax_type': {'bsonType': 'string'},
                        'deadline': {'bsonType': 'date'},
                        'description': {'bsonType': 'string'},
                        'year': {'bsonType': 'int'},
                        'created_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('country', ASCENDING)]},
                {'key': [('tax_type', ASCENDING)]},
                {'key': [('deadline', ASCENDING)]},
                {'key': [('year', DESCENDING)]}
            ]
        },
        'grocery_items': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'name', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'name': {'bsonType': 'string'},
                        'category': {'bsonType': 'string'},
                        'brand': {'bsonType': 'string'},
                        'price': {'bsonType': 'double'},
                        'store': {'bsonType': 'string'},
                        'is_purchased': {'bsonType': 'bool'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('name', ASCENDING)]},
                {'key': [('category', ASCENDING)]},
                {'key': [('is_purchased', ASCENDING)]}
            ]
        },
        'grocery_suggestions': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'suggestion', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'suggestion': {'bsonType': 'string'},
                        'category': {'bsonType': 'string'},
                        'priority': {'bsonType': 'int'},
                        'is_accepted': {'bsonType': 'bool'},
                        'created_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('category', ASCENDING)]},
                {'key': [('priority', DESCENDING)]},
                {'key': [('is_accepted', ASCENDING)]}
            ]
        },
        'meal_plans': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'name', 'meals', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'name': {'bsonType': 'string'},
                        'description': {'bsonType': 'string'},
                        'meals': {
                            'bsonType': 'array',
                            'items': {
                                'bsonType': 'object',
                                'properties': {
                                    'day': {'bsonType': 'string'},
                                    'meal_type': {'bsonType': 'string'},
                                    'recipe': {'bsonType': 'string'},
                                    'ingredients': {'bsonType': 'array'}
                                }
                            }
                        },
                        'week_start': {'bsonType': 'date'},
                        'is_active': {'bsonType': 'bool'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('week_start', DESCENDING)]},
                {'key': [('is_active', ASCENDING)]}
            ]
        },
        'feedback': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'type', 'message', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'type': {'bsonType': 'string'},
                        'message': {'bsonType': 'string'},
                        'rating': {'bsonType': 'int'},
                        'status': {'bsonType': 'string'},
                        'response': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('type', ASCENDING)]},
                {'key': [('status', ASCENDING)]},
                {'key': [('created_at', DESCENDING)]}
            ]
        },
        'tool_usage': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'tool_name', 'action', 'timestamp'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'tool_name': {'bsonType': 'string'},
                        'action': {'bsonType': 'string'},
                        'parameters': {'bsonType': 'object'},
                        'result': {'bsonType': 'object'},
                        'execution_time': {'bsonType': 'double'},
                        'timestamp': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('tool_name', ASCENDING)]},
                {'key': [('timestamp', DESCENDING)]}
            ]
        },
        'budgets': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'name', 'amount', 'period', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'name': {'bsonType': 'string'},
                        'amount': {'bsonType': 'double'},
                        'spent': {'bsonType': 'double'},
                        'period': {'bsonType': 'string'},
                        'category': {'bsonType': 'string'},
                        'start_date': {'bsonType': 'date'},
                        'end_date': {'bsonType': 'date'},
                        'is_active': {'bsonType': 'bool'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('period', ASCENDING)]},
                {'key': [('is_active', ASCENDING)]},
                {'key': [('start_date', DESCENDING)]}
            ]
        },
        'bills': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'name', 'amount', 'due_date', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'name': {'bsonType': 'string'},
                        'description': {'bsonType': 'string'},
                        'amount': {'bsonType': 'double'},
                        'due_date': {'bsonType': 'date'},
                        'is_paid': {'bsonType': 'bool'},
                        'is_recurring': {'bsonType': 'bool'},
                        'recurrence_period': {'bsonType': 'string'},
                        'category': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('due_date', ASCENDING)]},
                {'key': [('is_paid', ASCENDING)]},
                {'key': [('is_recurring', ASCENDING)]}
            ]
        },
        'bill_reminders': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'bill_id', 'reminder_date', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'bill_id': {'bsonType': 'objectId'},
                        'reminder_date': {'bsonType': 'date'},
                        'message': {'bsonType': 'string'},
                        'is_sent': {'bsonType': 'bool'},
                        'sent_at': {'bsonType': 'date'},
                        'created_at': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('bill_id', ASCENDING)]},
                {'key': [('reminder_date', ASCENDING)]},
                {'key': [('is_sent', ASCENDING)]}
            ]
        },
        'sessions': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'session_token', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'session_token': {'bsonType': 'string'},
                        'expires_at': {'bsonType': 'date'},
                        'is_active': {'bsonType': 'bool'},
                        'ip_address': {'bsonType': 'string'},
                        'user_agent': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'last_accessed': {'bsonType': 'date'}
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('session_token', ASCENDING)], 'unique': True},
                {'key': [('expires_at', ASCENDING)]},
                {'key': [('is_active', ASCENDING)]}
            ]
        },
        'food_orders': {
            'validator': {
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'user_id', 'name', 'vendor', 'total_cost', 'created_at', 'updated_at', 'shared_with', 'items'],
                    'properties': {
                        '_id': {'bsonType': 'objectId'},
                        'user_id': {'bsonType': 'string'},
                        'name': {'bsonType': 'string'},
                        'vendor': {'bsonType': 'string'},
                        'total_cost': {'bsonType': 'double', 'minimum': 0},
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'},
                        'shared_with': {
                            'bsonType': 'array',
                            'items': {'bsonType': 'string'}
                        },
                        'items': {
                            'bsonType': 'array',
                            'items': {
                                'bsonType': 'object',
                                'required': ['item_id', 'name', 'quantity', 'price'],
                                'properties': {
                                    'item_id': {'bsonType': 'string'},
                                    'name': {'bsonType': 'string'},
                                    'quantity': {'bsonType': 'int', 'minimum': 1},
                                    'price': {'bsonType': 'double', 'minimum': 0},
                                    'category': {'bsonType': ['string', 'null']}
                                }
                            }
                        }
                    }
                }
            },
            'indexes': [
                {'key': [('user_id', ASCENDING)]},
                {'key': [('created_at', DESCENDING)]},
                {'key': [('shared_with', ASCENDING)]}
            ]
        }
    }
    
    # Create collections with validation and indexes
    for collection_name, schema_config in collection_schemas.items():
        try:
            # Create collection if it doesn't exist
            if collection_name not in db.list_collection_names():
                db.create_collection(collection_name, validator=schema_config['validator'])
                logger.info(f"Created collection: {collection_name}")
            else:
                # Update validator for existing collection
                db.command('collMod', collection_name, validator=schema_config['validator'])
                logger.info(f"Updated validator for collection: {collection_name}")
            
            # Create indexes
            collection = db[collection_name]
            for index_config in schema_config.get('indexes', []):
                try:
                    collection.create_index(**index_config)
                except DuplicateKeyError:
                    pass  # Index already exists
                    
        except Exception as e:
            logger.error(f"Error setting up collection {collection_name}: {str(e)}")
            continue
    
    logger.info("Database initialization completed")

# CRUD Functions for Users
def create_user(db, user_data):
    """Create a new user in the users collection."""
    try:
        required_fields = ['username', 'email', 'password_hash']
        if not all(field in user_data for field in required_fields):
            raise ValueError(trans('general_missing_user_fields', default='Missing required user fields'))
        
        user_data['created_at'] = datetime.utcnow()
        user_data['updated_at'] = datetime.utcnow()
        user_data['is_active'] = user_data.get('is_active', True)
        
        result = db.users.insert_one(user_data)
        logger.info(f"{trans('general_user_created', default='Created user with ID')}: {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_user_creation_error', default='Error creating user')}: {str(e)}", exc_info=True)
        raise

def get_users(db, filter_kwargs):
    """Retrieve user records based on filter criteria."""
    try:
        return list(db.users.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_users_fetch_error', default='Error getting users')}: {str(e)}", exc_info=True)
        raise

def update_user(db, user_id, update_data):
    """Update a user in the users collection."""
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_user_updated', default='Updated user with ID')}: {user_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"{trans('general_user_update_error', default='Error updating user')}: {str(e)}", exc_info=True)
        raise

def delete_user(db, user_id):
    """Delete a user from the users collection."""
    try:
        result = db.users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_user_deleted', default='Deleted user with ID')}: {user_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"{trans('general_user_delete_error', default='Error deleting user')}: {str(e)}", exc_info=True)
        raise

# CRUD Functions for Records
def create_record(db, record_data):
    """Create a new record in the records collection."""
    try:
        required_fields = ['user_id', 'type', 'amount']
        if not all(field in record_data for field in required_fields):
            raise ValueError(trans('general_missing_record_fields', default='Missing required record fields'))
        
        record_data['created_at'] = datetime.utcnow()
        record_data['updated_at'] = datetime.utcnow()
        
        result = db.records.insert_one(record_data)
        logger.info(f"{trans('general_record_created', default='Created record with ID')}: {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_record_creation_error', default='Error creating record')}: {str(e)}", exc_info=True)
        raise

def get_records(db, filter_kwargs):
    """Retrieve records based on filter criteria."""
    try:
        return list(db.records.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_records_fetch_error', default='Error getting records')}: {str(e)}", exc_info=True)
        raise

def update_record(db, record_id, update_data):
    """Update a record in the records collection."""
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.records.update_one(
            {'_id': ObjectId(record_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_record_updated', default='Updated record with ID')}: {record_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"{trans('general_record_update_error', default='Error updating record')}: {str(e)}", exc_info=True)
        raise

def delete_record(db, record_id):
    """Delete a record from the records collection."""
    try:
        result = db.records.delete_one({'_id': ObjectId(record_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_record_deleted', default='Deleted record with ID')}: {record_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"{trans('general_record_delete_error', default='Error deleting record')}: {str(e)}", exc_info=True)
        raise

# CRUD Functions for Food Orders
def create_food_order(db, order_data):
    """
    Create a new food order in the food_orders collection.
    
    Args:
        db: MongoDB database instance
        order_data: Dictionary containing food order information
    
    Returns:
        str: ID of the created food order
    """
    try:
        required_fields = ['user_id', 'name', 'vendor', 'total_cost', 'created_at', 'updated_at', 'shared_with', 'items']
        if not all(field in order_data for field in required_fields):
            raise ValueError(trans('general_missing_food_order_fields', default='Missing required food order fields'))
        
        # Ensure items have item_id
        for item in order_data.get('items', []):
            if 'item_id' not in item:
                item['item_id'] = str(uuid.uuid4())
        
        result = db.food_orders.insert_one(order_data)
        logger.info(f"{trans('general_food_order_created', default='Created food order with ID')}: {result.inserted_id}", 
                   extra={'session_id': order_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_food_order_creation_error', default='Error creating food order')}: {str(e)}", 
                    exc_info=True, extra={'session_id': order_data.get('session_id', 'no-session-id')})
        raise

def get_food_orders(db, filter_kwargs):
    """
    Retrieve food order records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of food order records
    """
    try:
        return list(db.food_orders.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_food_orders_fetch_error', default='Error getting food orders')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_food_order(db, order_id, update_data):
    """
    Update a food order in the food_orders collection.
    
    Args:
        db: MongoDB database instance
        order_id: The ID of the food order to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.food_orders.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_food_order_updated', default='Updated food order with ID')}: {order_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_food_order_no_change', default='No changes made to food order with ID')}: {order_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_food_order_update_error', default='Error updating food order with ID')} {order_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def delete_food_order(db, order_id):
    """
    Delete a food order from the food_orders collection.
    
    Args:
        db: MongoDB database instance
        order_id: The ID of the food order to delete
    
    Returns:
        bool: True if deleted, False if not found
    """
    try:
        result = db.food_orders.delete_one({'_id': ObjectId(order_id)})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_food_order_deleted', default='Deleted food order with ID')}: {order_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_food_order_not_found', default='Food order not found with ID')}: {order_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_food_order_delete_error', default='Error deleting food order with ID')} {order_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_food_order(record):
    """Convert food order record to dictionary."""
    if not record:
        return {'name': None, 'vendor': None, 'total_cost': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'name': record.get('name', ''),
        'vendor': record.get('vendor', ''),
        'total_cost': record.get('total_cost', 0.0),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at'),
        'shared_with': record.get('shared_with', []),
        'items': record.get('items', [])
    }

# Utility Functions
def to_dict_user(record):
    """Convert user record to dictionary."""
    if not record:
        return {'username': None, 'email': None}
    return {
        'id': str(record.get('_id', '')),
        'username': record.get('username', ''),
        'email': record.get('email', ''),
        'is_active': record.get('is_active', True),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at'),
        'profile': record.get('profile', {})
    }

def to_dict_record(record):
    """Convert record to dictionary."""
    if not record:
        return {'type': None, 'amount': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'type': record.get('type', ''),
        'amount': record.get('amount', 0.0),
        'description': record.get('description', ''),
        'category': record.get('category', ''),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at')
    }

# Database connection helper
def get_database_connection(connection_string: str, database_name: str):
    """Get MongoDB database connection."""
    try:
        client = MongoClient(connection_string)
        db = client[database_name]
        # Test connection
        db.command('ping')
        logger.info(f"Successfully connected to database: {database_name}")
        return db
    except Exception as e:
        logger.error(f"Failed to connect to database: {str(e)}", exc_info=True)
        raise

# Initialize database with all schemas
def setup_database(connection_string: str, database_name: str):
    """Setup database with all collections and schemas."""
    try:
        db = get_database_connection(connection_string, database_name)
        initialize_app_data(db)
        return db
    except Exception as e:
        logger.error(f"Failed to setup database: {str(e)}", exc_info=True)
        raise