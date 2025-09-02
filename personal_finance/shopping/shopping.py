from flask import Blueprint, request, session, redirect, url_for, render_template, flash, current_app, jsonify, Response
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, FloatField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError, Email
from flask_login import current_user, login_required
from datetime import datetime
from helpers.branding_helpers import draw_ficore_pdf_header
from bson import ObjectId
from pymongo import errors
from utils import get_mongo_db, requires_role, logger, check_ficore_credit_balance, is_admin, format_date, format_currency
from translations import trans
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
from contextlib import nullcontext
import uuid
from models import log_tool_usage, get_shopping_lists, create_shopping_list, create_shopping_item, create_shopping_items_bulk
import json

shopping_bp = Blueprint(
    'shopping',
    __name__,
    template_folder='templates/',
    url_prefix='/shopping'
)

csrf = CSRFProtect()

def auto_categorize_item(item_name):
    item_name = item_name.lower().strip()
    categories = {
        'fruits': ['apple', 'banana', 'orange', 'mango', 'pineapple', 'berry', 'grape'],
        'vegetables': ['carrot', 'potato', 'tomato', 'onion', 'spinach', 'lettuce'],
        'dairy': ['milk', 'cheese', 'yogurt', 'butter', 'cream'],
        'meat': ['chicken', 'beef', 'pork', 'fish', 'egg'],
        'grains': ['rice', 'bread', 'pasta', 'flour', 'cereal'],
        'beverages': ['juice', 'soda', 'water', 'tea', 'coffee'],
        'household': ['detergent', 'soap', 'tissue', 'paper towel'],
        'other': []
    }
    for category, keywords in categories.items():
        if any(keyword in item_name for keyword in keywords):
            return category
    return 'other'

def clean_currency(value):
    """Clean and convert currency input to float, handling empty or invalid inputs."""
    if value is None or value == '':
        logger.debug("clean_currency received empty or None input, returning None")
        return None
    try:
        cleaned_value = str(value).replace(',', '').replace(' ', '')
        return round(float(cleaned_value), 2)
    except (ValueError, TypeError) as e:
        logger.error(f"clean_currency failed with input {value}: {str(e)}")
        raise ValidationError(trans('shopping_price_invalid', default='Invalid price format'))

def deduct_ficore_credits(db, user_id, amount, action, item_id=None, mongo_session=None):
    """
    Deduct Ficore Credits from user balance with enhanced error logging and transaction handling.
    
    Args:
        db: MongoDB database instance
        user_id: User ID (must match _id field in users collection)
        amount: Amount to deduct (1 or 2)
        action: Action description for logging
        item_id: Optional item ID for reference
        mongo_session: Optional MongoDB session for transaction
    
    Returns:
        bool: True if successful, False otherwise
    """
    session_id = session.get('sid', 'no-session-id')
    
    try:
        amount = int(amount)
        if amount not in [1, 2]:
            logger.error(f"Invalid deduction amount {amount} for user {user_id}, action: {action}. Must be 1 or 2.",
                        extra={'session_id': session_id, 'user_id': user_id})
            return False
        
        if not user_id:
            logger.error(f"No user_id provided for credit deduction, action: {action}",
                        extra={'session_id': session_id})
            return False
        
        user = db.users.find_one({'_id': user_id}, session=mongo_session)
        if not user:
            logger.error(f"User {user_id} not found in database for credit deduction, action: {action}. Check if user_id matches _id field type.",
                        extra={'session_id': session_id, 'user_id': user_id})
            return False
        
        current_balance = float(user.get('ficore_credit_balance', 0))
        logger.debug(f"Current balance for user {user_id}: {current_balance}, attempting to deduct: {amount}",
                    extra={'session_id': session_id, 'user_id': user_id})
        
        if current_balance < amount:
            logger.warning(f"Insufficient credits for user {user_id}: required {amount}, available {current_balance}, action: {action}",
                         extra={'session_id': session_id, 'user_id': user_id})
            return False
        
        session_to_use = mongo_session if mongo_session else db.client.start_session()
        owns_session = not mongo_session
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                with session_to_use.start_transaction() if not mongo_session else nullcontext():
                    result = db.users.update_one(
                        {'_id': user_id},
                        [{'$set': {'ficore_credit_balance': {'$toDouble': {'$subtract': ['$ficore_credit_balance', amount]}}}}],
                        session=session_to_use
                    )
                    
                    if result.modified_count == 0:
                        error_msg = f"Failed to deduct {amount} credits for user {user_id}, action: {action}: No documents modified. User may not exist or balance unchanged."
                        logger.error(error_msg, extra={'session_id': session_id, 'user_id': user_id})
                        
                        db.ficore_credit_transactions.insert_one({
                            '_id': ObjectId(),
                            'user_id': user_id,
                            'action': action,
                            'amount': float(-amount),
                            'item_id': str(item_id) if item_id else None,
                            'timestamp': datetime.utcnow(),
                            'session_id': session_id,
                            'status': 'failed'
                        }, session=session_to_use)
                        
                        raise ValueError(error_msg)
                    
                    transaction = {
                        '_id': ObjectId(),
                        'user_id': user_id,
                        'action': action,
                        'amount': float(-amount),
                        'item_id': str(item_id) if item_id else None,
                        'timestamp': datetime.utcnow(),
                        'session_id': session_id,
                        'status': 'completed'
                    }
                    db.ficore_credit_transactions.insert_one(transaction, session=session_to_use)
                    
                    db.audit_logs.insert_one({
                        'admin_id': 'system',
                        'action': f'deduct_ficore_credits_{action}',
                        'details': {
                            'user_id': user_id, 
                            'amount': amount, 
                            'item_id': str(item_id) if item_id else None,
                            'previous_balance': current_balance,
                            'new_balance': current_balance - amount
                        },
                        'timestamp': datetime.utcnow()
                    }, session=session_to_use)
                    
                    if owns_session:
                        session_to_use.commit_transaction()
                    
                    logger.info(f"Successfully deducted {amount} Ficore Credits for {action} by user {user_id}. New balance: {current_balance - amount}",
                               extra={'session_id': session_id, 'user_id': user_id})
                    return True
                    
            except errors.OperationFailure as e:
                error_details = e.details if hasattr(e, 'details') else {}
                
                if "TransientTransactionError" in error_details.get("errorLabels", []):
                    if attempt < max_retries - 1:
                        logger.warning(f"Transient transaction error for user {user_id}, action: {action}, attempt {attempt + 1}/{max_retries}. Retrying...",
                                     extra={'session_id': session_id, 'user_id': user_id})
                        continue
                
                logger.error(f"MongoDB operation failed for user {user_id}, action: {action}: {str(e)}. Error details: {error_details}",
                            exc_info=True, extra={'session_id': session_id, 'user_id': user_id})
                
                if owns_session:
                    try:
                        session_to_use.abort_transaction()
                    except Exception as abort_error:
                        logger.error(f"Failed to abort transaction: {abort_error}", extra={'session_id': session_id, 'user_id': user_id})
                return False
                
            except (ValueError, errors.PyMongoError) as e:
                logger.error(f"Database error during credit deduction for user {user_id}, action: {action}: {str(e)}",
                            exc_info=True, extra={'session_id': session_id, 'user_id': user_id})
                
                if owns_session:
                    try:
                        session_to_use.abort_transaction()
                    except Exception as abort_error:
                        logger.error(f"Failed to abort transaction: {abort_error}", extra={'session_id': session_id, 'user_id': user_id})
                return False
                
            except Exception as e:
                logger.error(f"Unexpected error during transaction for user {user_id}, action: {action}: {str(e)}",
                            exc_info=True, extra={'session_id': session_id, 'user_id': user_id})
                
                if owns_session:
                    try:
                        session_to_use.end_session()
                    except Exception as end_error:
                        logger.error(f"Failed to end session: {end_error}", extra={'session_id': session_id, 'user_id': user_id})
                return False
                
            finally:
                if owns_session:
                    try:
                        session_to_use.end_session()
                    except Exception as end_error:
                        logger.error(f"Failed to end session: {end_error}", extra={'session_id': session_id, 'user_id': user_id})
        
        logger.error(f"All {max_retries} transaction attempts failed for user {user_id}, action: {action}",
                    extra={'session_id': session_id, 'user_id': user_id})
        return False
        
    except Exception as e:
        logger.error(f"Unexpected error in deduct_ficore_credits for user {user_id}, action: {action}: {str(e)}",
                    exc_info=True, extra={'session_id': session_id, 'user_id': user_id})
        return False

def custom_login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        return redirect(url_for('users.login', next=request.url))
    return decorated_function

class ShoppingListForm(FlaskForm):
    name = StringField(
        trans('shopping_list_name', default='List Name'),
        validators=[DataRequired(message=trans('shopping_name_required', default='List name is required'))]
    )
    budget = FloatField(
        trans('shopping_budget', default='Budget'),
        filters=[clean_currency],
        validators=[
            DataRequired(message=trans('shopping_budget_required', default='Budget is required')),
            NumberRange(min=0.01, max=10000000000, message=trans('shopping_budget_max', default='Budget must be between 0.01 and 10 billion'))
        ]
    )
    submit = SubmitField(trans('shopping_submit', default='Create List'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        self.name.label.text = trans('shopping_list_name', lang) or 'List Name'
        self.budget.label.text = trans('shopping_budget', lang) or 'Budget'
        self.submit.label.text = trans('shopping_submit', lang) or 'Create List'

    def validate_budget(self, budget):
        if budget.data is None or budget.data == '':
            raise ValidationError(trans('shopping_budget_required', default='Budget is required'))
        try:
            cleaned_value = str(budget.data).replace(',', '').replace(' ', '')
            budget.data = round(float(cleaned_value), 2)
            if budget.data < 0.01:
                raise ValidationError(trans('shopping_budget_min', default='Budget must be at least 0.01'))
            if budget.data > 10000000000:
                raise ValidationError(trans('shopping_budget_max', default='Budget must be between 0.01 and 10 billion'))
        except (ValueError, TypeError):
            logger.error(f"Budget validation failed: {budget.data}", extra={'session_id': session.get('sid', 'no-session-id')})
            raise ValidationError(trans('shopping_budget_invalid', default='Invalid budget format'))

class ShoppingItemsForm(FlaskForm):
    name = StringField(
        trans('shopping_item_name', default='Item Name'),
        validators=[DataRequired(message=trans('shopping_item_name_required', default='Item name is required'))]
    )
    quantity = IntegerField(
        trans('shopping_quantity', default='Quantity'),
        validators=[
            DataRequired(message=trans('shopping_quantity_required', default='Quantity is required')),
            NumberRange(min=1, max=1000, message=trans('shopping_quantity_range', default='Quantity must be between 1 and 1000'))
        ]
    )
    price = FloatField(
        trans('shopping_price', default='Price'),
        filters=[clean_currency],
        validators=[
            DataRequired(message=trans('shopping_price_required', default='Price is required')),
            NumberRange(min=0, max=1000000, message=trans('shopping_price_range', default='Price must be between 0 and 1 million'))
        ]
    )
    unit = SelectField(
        trans('shopping_unit', default='Unit'),
        choices=[
            ('piece', trans('shopping_unit_piece', default='Piece')),
            ('carton', trans('shopping_unit_carton', default='Carton')),
            ('kg', trans('shopping_unit_kg', default='Kilogram')),
            ('liter', trans('shopping_unit_liter', default='Liter')),
            ('pack', trans('shopping_unit_pack', default='Pack')),
            ('other', trans('shopping_unit_other', default='Other'))
        ],
        validators=[DataRequired(message=trans('shopping_unit_required', default='Unit is required'))]
    )
    store = StringField(
        trans('shopping_store', default='Store'),
        validators=[DataRequired(message=trans('shopping_store_required', default='Store is required'))]
    )
    category = SelectField(
        trans('shopping_category', default='Category'),
        choices=[
            ('fruits', trans('shopping_category_fruits', default='Fruits')),
            ('vegetables', trans('shopping_category_vegetables', default='Vegetables')),
            ('dairy', trans('shopping_category_dairy', default='Dairy')),
            ('meat', trans('shopping_category_meat', default='Meat')),
            ('grains', trans('shopping_category_grains', default='Grains')),
            ('beverages', trans('shopping_category_beverages', default='Beverages')),
            ('household', trans('shopping_category_household', default='Household')),
            ('other', trans('shopping_category_other', default='Other'))
        ]
    )
    status = SelectField(
        trans('shopping_status', default='Status'),
        choices=[
            ('to_buy', trans('shopping_status_to_buy', default='To Buy')),
            ('bought', trans('shopping_status_bought', default='Bought'))
        ],
        default='to_buy',
        validators=[DataRequired(message=trans('shopping_status_required', default='Status is required'))]
    )
    frequency = IntegerField(
        trans('shopping_frequency', default='Frequency (days)'),
        validators=[
            DataRequired(message=trans('shopping_frequency_required', default='Frequency is required')),
            NumberRange(min=1, max=365, message=trans('shopping_frequency_range', default='Frequency must be between 1 and 365 days'))
        ]
    )
    submit = SubmitField(trans('shopping_item_submit', default='Add Item'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug(f"Initializing ShoppingItemsForm with kwargs: {kwargs}", extra={'session_id': session.get('sid', 'no-session-id')})
        lang = session.get('lang', 'en')
        self.name.label.text = trans('shopping_item_name', lang) or 'Item Name'
        self.quantity.label.text = trans('shopping_quantity', lang) or 'Quantity'
        self.price.label.text = trans('shopping_price', lang) or 'Price'
        self.unit.label.text = trans('shopping_unit', lang) or 'Unit'
        self.store.label.text = trans('shopping_store', lang) or 'Store'
        self.category.label.text = trans('shopping_category', lang) or 'Category'
        self.status.label.text = trans('shopping_status', lang) or 'Status'
        self.frequency.label.text = trans('shopping_frequency', lang) or 'Frequency (days)'
        self.submit.label.text = trans('shopping_item_submit', lang) or 'Add Item'

    def validate_price(self, price):
        if price.data is None:
            logger.debug(f"Price validation failed: Price is None", extra={'session_id': session.get('sid', 'no-session-id')})
            raise ValidationError(trans('shopping_price_required', default='Price is required'))
        try:
            price.data = float(price.data)
            if price.data < 0:
                raise ValidationError(trans('shopping_price_range', default='Price must be non-negative'))
        except (ValueError, TypeError):
            logger.error(f"Price validation failed: {price.data}", extra={'session_id': session.get('sid', 'no-session-id')})
            raise ValidationError(trans('shopping_price_invalid', default='Invalid price format'))

    def validate_status(self, status):
        valid_choices = ['to_buy', 'bought']
        if status.data not in valid_choices:
            logger.debug(f"Invalid status value submitted: {status.data}", extra={'session_id': session.get('sid', 'no-session-id')})
            raise ValidationError(trans('shopping_status_invalid', default='Not a valid status choice.'))

class ShareListForm(FlaskForm):
    email = StringField(
        trans('shopping_collaborator_email', default='Collaborator Email'),
        validators=[
            DataRequired(message=trans('shopping_email_required', default='Email is required')),
            Email(message=trans('shopping_invalid_email', default='Invalid email address'))
        ]
    )
    submit = SubmitField(trans('shopping_share_submit', default='Share List'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        self.email.label.text = trans('shopping_collaborator_email', lang) or 'Collaborator Email'
        self.submit.label.text = trans('shopping_share_submit', lang) or 'Share List'

@shopping_bp.route('/', methods=['GET'])
@custom_login_required
@requires_role(['personal', 'admin'])
def index():
    """Shopping module landing page with navigation cards."""
    return render_template('shopping/index.html')

@shopping_bp.route('/new', methods=['GET', 'POST'])
@custom_login_required
@requires_role(['personal', 'admin'])
def new():
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
        logger.debug(f"New session created with sid: {session['sid']}")
    session.permanent = True
    session.modified = True

    list_form = ShoppingListForm()
    item_form = ShoppingItemsForm()
    share_form = ShareListForm()
    items_form = ShoppingItemsForm()
    db = get_mongo_db()

    valid_tabs = ['create-list', 'add-items', 'view-lists', 'manage-list']
    active_tab = request.args.get('tab', 'create-list')
    if active_tab not in valid_tabs:
        active_tab = 'create-list'

    filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)}
    lists = {str(lst['_id']): lst for lst in db.shopping_lists.find(filter_criteria).sort('created_at', -1)}
    
    selected_list_id = request.args.get('list_id') or session.get('selected_list_id')
    if not selected_list_id and lists:
        selected_list_id = list(lists.keys())[0]
        session['selected_list_id'] = selected_list_id

    selected_list = lists.get(selected_list_id, {})
    items = []
    if selected_list_id:
        list_items = list(db.shopping_items.find({'list_id': selected_list_id}))
        items = [{
            'id': str(item['_id']),
            'name': item.get('name', ''),
            'quantity': int(item.get('quantity', 1)),
            'price_raw': float(item.get('price', 0.0)),
            'unit': item.get('unit', 'piece'),
            'category': item.get('category', 'other'),
            'status': item.get('status', 'to_buy'),
            'store': item.get('store', 'Unknown'),
            'frequency': int(item.get('frequency', 7))
        } for item in list_items]
        selected_list['items'] = items

    categories = {}
    if selected_list_id:
        categories = {
            trans('shopping_category_fruits', default='Fruits'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'fruits'),
            trans('shopping_category_vegetables', default='Vegetables'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'vegetables'),
            trans('shopping_category_dairy', default='Dairy'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'dairy'),
            trans('shopping_category_meat', default='Meat'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'meat'),
            trans('shopping_category_grains', default='Grains'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'grains'),
            trans('shopping_category_beverages', default='Beverages'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'beverages'),
            trans('shopping_category_household', default='Household'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'household'),
            trans('shopping_category_other', default='Other'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'other')
        }
        categories = {k: v for k, v in categories.items() if v > 0}

    try:
        log_tool_usage(
            tool_name='shopping',
            db=db,
            user_id=current_user.id,
            session_id=session.get('sid', 'no-session'),
            action='main_view'
        )
    except Exception as e:
        flash(trans('shopping_log_error', default='Error logging activity.'), 'danger')

    if request.method == 'POST':
        action = request.form.get('action')
        logger.debug(f"Processing action: {action} with form data: {request.form.to_dict()}", extra={'session_id': session.get('sid', 'no-session-id')})
        if action == 'create_list':
            logger.debug(f"Processing create_list action with form data: {request.form.to_dict()}", extra={'session_id': session.get('sid', 'no-session-id')})
            if list_form.validate_on_submit():
                session_id = session.get('sid', str(uuid.uuid4()))
                if not session.get('sid'):
                    session['sid'] = session_id
                    logger.debug(f"Assigned new session_id: {session_id}")
                list_data = {
                    '_id': ObjectId(),
                    'name': list_form.name.data.strip(),
                    'user_id': str(current_user.id),
                    'budget': float(list_form.budget.data),
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow(),
                    'collaborators': [],
                    'items': [],
                    'total_spent': 0.0,
                    'status': 'active'
                }
                try:
                    logger.debug(f"Creating shopping list: {list_data}", extra={'session_id': session_id})
                    created_list_id = create_shopping_list(db, list_data)
                    session['selected_list_id'] = str(list_data['_id'])
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({
                            'success': True,
                            'redirect_url': url_for('shopping.dashboard')
                        })
                    flash(trans('shopping_list_created', default='Shopping list created successfully!'), 'success')
                    return redirect(url_for('shopping.dashboard'))
                except errors.WriteError as e:
                    logger.error(f"Failed to save list {list_data['_id']}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({
                            'success': False,
                            'error': trans('shopping_list_error', default='Error saving list due to validation failure.')
                        }), 500
                    flash(trans('shopping_list_error', default='Error saving list due to validation failure.'), 'danger')
                    return redirect(url_for('shopping.new'))
                except Exception as e:
                    logger.error(f"Unexpected error saving list {list_data['_id']}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({
                            'success': False,
                            'error': trans('shopping_list_error', default=f'Error saving list: {str(e)}')
                        }), 500
                    flash(trans('shopping_list_error', default=f'Error saving list: {str(e)}'), 'danger')
                    return redirect(url_for('shopping.new'))
            else:
                form_errors = {field: [trans(error, default=error) for error in field_errors] for field, field_errors in list_form.errors.items()}
                logger.debug(f"Form validation failed: {form_errors}", extra={'session_id': session.get('sid', 'no-session-id')})
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({
                        'success': False,
                        'error': trans('shopping_form_invalid', default='Invalid form data.'),
                        'errors': form_errors
                    }), 400
                for field, field_errors in list_form.errors.items():
                    for error in field_errors:
                        flash(f"{field.capitalize()}: {trans(error, default=error)}", 'danger')
                return render_template(
                    'shopping/new.html',
                    form=list_form,
                    list_form=list_form,
                    item_form=item_form,
                    share_form=share_form,
                    items_form=items_form,
                    lists=lists,
                    selected_list=selected_list,
                    selected_list_id=selected_list_id,
                    items=items,
                    categories=categories,
                    tips=[
                        trans('shopping_tip_plan_ahead', default='Plan your shopping list ahead to avoid impulse buys.'),
                        trans('shopping_tip_compare_prices', default='Compare prices across stores to save money.'),
                        trans('shopping_tip_bulk_buy', default='Buy non-perishable items in bulk to reduce costs.'),
                        trans('shopping_tip_check_sales', default='Check for sales or discounts before shopping.')
                    ],
                    insights=[],
                    tool_title=trans('shopping_title', default='Shopping List Planner'),
                    active_tab='create-list'
                )

        elif action == 'add_items':
            list_id = request.form.get('list_id')
            if not ObjectId.is_valid(list_id):
                flash(trans('shopping_invalid_list_id', default='Invalid list ID.'), 'danger')
                return redirect(url_for('shopping.new'))
            shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
            if not shopping_list:
                flash(trans('shopping_list_not_found', default='List not found.'), 'danger')
                return redirect(url_for('shopping.new'))
            existing_items = db.shopping_items.find({'list_id': list_id}, {'name': 1})
            existing_names = {item['name'].lower() for item in existing_items}
            new_items = []
            for i in range(1, 6):
                new_name = request.form.get(f'new_item_name_{i}', '').strip()
                if new_name:
                    new_items.append({
                        'name': new_name,
                        'quantity': request.form.get(f'new_item_quantity_{i}', 1),
                        'price': request.form.get(f'new_item_price_{i}', '0'),
                        'unit': request.form.get(f'new_item_unit_{i}', 'piece'),
                        'category': request.form.get(f'new_item_category_{i}', auto_categorize_item(new_name)),
                        'status': request.form.get(f'new_item_status_{i}', 'to_buy'),
                        'store': request.form.get(f'new_item_store_{i}', 'Unknown'),
                        'frequency': request.form.get(f'new_item_frequency_{i}', 7)
                    })
            for item_data in new_items:
                if item_data['name'].lower() in existing_names:
                    flash(trans('shopping_duplicate_item_name', default='Item name already exists in this list.'), 'danger')
                    return redirect(url_for('shopping.new'))
            added = 0
            session_id = session.get('sid', str(uuid.uuid4()))
            if not session.get('sid'):
                session['sid'] = session_id
                logger.debug(f"Assigned new session_id: {session_id}")
            try:
                with db.client.start_session() as mongo_session:
                    with mongo_session.start_transaction():
                        for item_data in new_items:
                            try:
                                new_quantity = int(item_data['quantity'])
                                new_price = float(clean_currency(item_data['price']))
                                new_unit = item_data['unit']
                                new_category = item_data['category']
                                new_status = item_data['status']
                                new_store = item_data['store']
                                new_frequency = int(item_data['frequency'])
                                if new_quantity < 1 or new_quantity > 1000 or new_price is None or new_price < 0 or new_price > 1000000 or new_frequency < 1 or new_frequency > 365:
                                    raise ValueError('Invalid input range')
                                new_item_data = {
                                    '_id': ObjectId(),
                                    'list_id': list_id,
                                    'user_id': str(current_user.id),
                                    'name': item_data['name'],
                                    'quantity': new_quantity,
                                    'price': new_price,
                                    'unit': new_unit,
                                    'category': new_category,
                                    'status': new_status,
                                    'store': new_store,
                                    'frequency': new_frequency,
                                    'created_at': datetime.utcnow(),
                                    'updated_at': datetime.utcnow()
                                }
                                logger.debug(f"Creating shopping item: {new_item_data}", extra={'session_id': session_id})
                                created_item_id = create_shopping_item(db, new_item_data, mongo_session=mongo_session)
                                added += 1
                                existing_names.add(item_data['name'].lower())
                            except ValueError as e:
                                flash(trans('shopping_item_error', default='Error adding new item: ') + str(e), 'danger')
                        if added > 0:
                            items = list(db.shopping_items.find({'list_id': list_id}, session=mongo_session))
                            total_spent = sum(item['price'] * item['quantity'] for item in items)
                            db.shopping_lists.update_one(
                                {'_id': ObjectId(list_id)},
                                {'$set': {'total_spent': total_spent, 'updated_at': datetime.utcnow()}},
                                session=mongo_session
                            )
                            get_shopping_lists.cache_clear()
                            flash(trans('shopping_items_added', default=f'{added} item(s) added successfully!'), 'success')
                            if total_spent > shopping_list['budget']:
                                flash(trans('shopping_over_budget', default='Warning: Total spent exceeds budget by ') + format_currency(total_spent - shopping_list['budget']) + '.', 'warning')
            except errors.WriteError as e:
                logger.error(f"Failed to save items for list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                flash(trans('shopping_list_error', default='Error saving items due to validation failure.'), 'danger')
                return redirect(url_for('shopping.new'))
            except Exception as e:
                logger.error(f"Unexpected error saving items for list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                flash(trans('shopping_list_error', default=f'Error saving items: {str(e)}'), 'danger')
                return redirect(url_for('shopping.new'))
            return redirect(url_for('shopping.new'))

    lists_dict = {}
    for lst in lists.values():
        list_items = list(db.shopping_items.find({'list_id': str(lst['_id'])}))
        list_data = {
            'id': str(lst['_id']),
            'name': lst.get('name', ''),
            'budget_raw': float(lst.get('budget', 0.0)),
            'total_spent_raw': float(lst.get('total_spent', 0.0)),
            'status': lst.get('status', 'active'),
            'created_at': lst.get('created_at'),
            'collaborators': lst.get('collaborators', []),
            'items': [{
                'id': str(item['_id']),
                'name': item.get('name', ''),
                'quantity': int(item.get('quantity', 1)),
                'price_raw': float(item.get('price', 0.0)),
                'unit': item.get('unit', 'piece'),
                'category': item.get('category', 'other'),
                'status': item.get('status', 'to_buy'),
                'store': item.get('store', 'Unknown'),
                'frequency': int(item.get('frequency', 7))
            } for item in list_items]
        }
        lists_dict[list_data['id']] = list_data

    selected_list = lists_dict.get(selected_list_id, {'items': [], 'budget_raw': 0.0, 'total_spent_raw': 0.0})
    items = selected_list.get('items', [])
    insights = []
    if selected_list.get('budget_raw', 0.0) > 0:
        if selected_list['total_spent_raw'] > selected_list['budget_raw']:
            insights.append(trans('shopping_insight_over_budget', default='You are over budget. Consider removing non-essential items.'))
        elif selected_list['total_spent_raw'] < selected_list['budget_raw'] * 0.5:
            insights.append(trans('shopping_insight_under_budget', default='You are under budget. Consider allocating funds to savings.'))

    return render_template(
        'shopping/new.html',
        form=list_form,
        list_form=list_form,
        item_form=item_form,
        share_form=share_form,
        items_form=items_form,
        lists=lists_dict,
        selected_list=selected_list,
        selected_list_id=selected_list_id,
        items=items,
        categories=categories,
        tips=[
            trans('shopping_tip_plan_ahead', default='Plan your shopping list ahead to avoid impulse buys.'),
            trans('shopping_tip_compare_prices', default='Compare prices across stores to save money.'),
            trans('shopping_tip_bulk_buy', default='Buy non-perishable items in bulk to reduce costs.'),
            trans('shopping_tip_check_sales', default='Check for sales or discounts before shopping.')
        ],
        insights=insights,
        tool_title=trans('shopping_title', default='Shopping List Planner'),
        active_tab=active_tab
    )

@shopping_bp.route('/dashboard', methods=['GET'])
@custom_login_required
@requires_role(['personal', 'admin'])
def dashboard():
    """Shopping dashboard page."""
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
        logger.debug(f"New session created with sid: {session['sid']}")
    session.permanent = True
    session.modified = True
    db = get_mongo_db()

    try:
        log_tool_usage(
            tool_name='shopping',
            db=db,
            user_id=current_user.id,
            session_id=session.get('sid', 'no-session'),
            action='dashboard_view'
        )
    except Exception as e:
        flash(trans('shopping_log_error', default='Error logging activity.'), 'danger')

    filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)}
    lists = list(db.shopping_lists.find(filter_criteria).sort('created_at', -1).limit(10))
    
    lists_data = []
    total_budget = 0.0
    total_spent = 0.0
    active_lists = 0
    completed_lists = 0
    
    for lst in lists:
        list_items = list(db.shopping_items.find({'list_id': str(lst['_id'])}))
        items_count = len(list_items)
        bought_items = len([item for item in list_items if item.get('status') == 'bought'])
        list_total = sum(item.get('price', 0) * item.get('quantity', 1) for item in list_items)
        
        list_data = {
            'id': str(lst['_id']),
            'name': lst.get('name', ''),
            'budget': float(lst.get('budget', 0.0)),
            'total_spent': list_total,
            'items_count': items_count,
            'bought_items': bought_items,
            'progress': (bought_items / items_count * 100) if items_count > 0 else 0,
            'status': lst.get('status', 'active'),
            'created_at': lst.get('created_at'),
            'items': list_items[:5]
        }
        lists_data.append(list_data)
        
        total_budget += list_data['budget']
        total_spent += list_data['total_spent']
        
        if list_data['status'] == 'active':
            active_lists += 1
        else:
            completed_lists += 1

    categories = {}
    for lst in lists:
        list_items = list(db.shopping_items.find({'list_id': str(lst['_id'])}))
        for item in list_items:
            category = item.get('category', 'other')
            if category not in categories:
                categories[category] = 0
            categories[category] += item.get('price', 0) * item.get('quantity', 1)

    tips = [
        trans('shopping_tip_plan_ahead', default='Plan your shopping list ahead to avoid impulse buys.'),
        trans('shopping_tip_compare_prices', default='Compare prices across stores to save money.'),
        trans('shopping_tip_bulk_buy', default='Buy non-perishable items in bulk to reduce costs.'),
        trans('shopping_tip_check_sales', default='Check for sales or discounts before shopping.')
    ]

    insights = []
    if total_budget > 0 and total_spent > total_budget:
        insights.append(trans('shopping_insight_over_budget', default='You are spending more than your budget. Consider reviewing your shopping habits.'))
    if active_lists > 5:
        insights.append(trans('shopping_insight_many_lists', default='You have many active lists. Consider consolidating them for better organization.'))

    return render_template(
        'shopping/dashboard.html',
        lists_data=lists_data,
        total_budget=format_currency(total_budget),
        total_spent=format_currency(total_spent),
        active_lists=active_lists,
        completed_lists=completed_lists,
        categories=categories,
        tips=tips,
        insights=insights,
        tool_title=trans('shopping_dashboard', default='Shopping Dashboard')
    )

@shopping_bp.route('/manage', methods=['GET'])
@custom_login_required
@requires_role(['personal', 'admin'])
def manage():
    """Manage shopping lists page."""
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
        logger.debug(f"New session created with sid: {session['sid']}")
    session.permanent = True
    session.modified = True
    db = get_mongo_db()

    try:
        log_tool_usage(
            tool_name='shopping',
            db=db,
            user_id=current_user.id,
            session_id=session.get('sid', 'no-session'),
            action='manage_view'
        )
    except Exception as e:
        flash(trans('shopping_log_error', default='Error logging activity.'), 'danger')

    filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)}
    lists = list(db.shopping_lists.find(filter_criteria).sort('created_at', -1))
    
    lists_data = []
    for lst in lists:
        list_items = list(db.shopping_items.find({'list_id': str(lst['_id'])}))
        items_count = len(list_items)
        bought_items = len([item for item in list_items if item.get('status') == 'bought'])
        list_total = sum(item.get('price', 0) * item['quantity'] for item in list_items)
        
        list_data = {
            'id': str(lst['_id']),
            'name': lst.get('name', ''),
            'budget': float(lst.get('budget', 0.0)),
            'total_spent': list_total,
            'items_count': items_count,
            'bought_items': bought_items,
            'progress': (bought_items / items_count * 100) if items_count > 0 else 0,
            'status': lst.get('status', 'active'),
            'created_at': lst.get('created_at'),
            'collaborators': lst.get('collaborators', [])
        }
        lists_data.append(list_data)

    return render_template(
        'shopping/manage.html',
        lists_data=lists_data,
        tool_title=trans('shopping_manage_lists', default='Manage Shopping Lists')
    )

@shopping_bp.route('/get_list_details', methods=['GET'])
@custom_login_required
@requires_role(['personal', 'admin'])
def get_list_details():
    db = get_mongo_db()
    list_id = request.args.get('list_id')
    tab = request.args.get('tab', 'manage-list')
    
    if not ObjectId.is_valid(list_id):
        return jsonify({'success': False, 'error': trans('shopping_invalid_list_id', default='Invalid list ID.')}), 400
    
    filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)}
    shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
    
    if not shopping_list:
        return jsonify({'success': False, 'error': trans('shopping_list_not_found', default='List not found.')}), 404
    
    list_items = list(db.shopping_items.find({'list_id': str(list_id)}))
    selected_list = {
        'id': str(shopping_list['_id']),
        'name': shopping_list.get('name', ''),
        'budget_raw': float(shopping_list.get('budget', 0.0)),
        'total_spent_raw': float(shopping_list.get('total_spent', 0.0)),
        'status': shopping_list.get('status', 'active'),
        'created_at': shopping_list.get('created_at'),
        'collaborators': shopping_list.get('collaborators', []),
        'items': [{
            'id': str(item['_id']),
            'name': item.get('name', ''),
            'quantity': int(item.get('quantity', 1)),
            'price_raw': float(item.get('price', 0.0)),
            'unit': item.get('unit', 'piece'),
            'category': item.get('category', 'other'),
            'status': item.get('status', 'to_buy'),
            'store': item.get('store', 'Unknown'),
            'frequency': int(item.get('frequency', 7))
        } for item in list_items]
    }
    
    try:
        html = render_template(
            'shopping/manage_list_details.html',
            form=ShoppingListForm(data={'name': selected_list['name'], 'budget': selected_list['budget_raw']}),
            list_form=ShoppingListForm(data={'name': selected_list['name'], 'budget': selected_list['budget_raw']}),
            item_form=ShoppingItemsForm(),
            selected_list=selected_list,
            selected_list_id=list_id,
            items=selected_list['items']
        )
        return jsonify({'success': True, 'html': html, 'items': selected_list['items']})
    except Exception as e:
        logger.error(f"Error rendering list details for {list_id}: {str(e)}")
        return jsonify({'success': False, 'error': trans('shopping_load_error', default='Failed to load list details.')}), 500

@shopping_bp.route('/edit/<list_id>', methods=['GET', 'POST'])
@custom_login_required
@requires_role(['personal', 'admin'])
def edit_list(list_id):
    """Edit an existing shopping list and its items."""
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
        logger.debug(f"New session created with sid: {session['sid']}")
    session.permanent = True
    session.modified = True

    db = get_mongo_db()
    session_id = session.get('sid', 'no-session-id')

    if not ObjectId.is_valid(list_id):
        logger.error(f"Invalid list ID: {list_id}", extra={'session_id': session_id})
        flash(trans('shopping_invalid_list_id', default='Invalid list ID.'), 'danger')
        return redirect(url_for('shopping.manage'))

    filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)}
    shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})

    if not shopping_list:
        logger.error(f"List not found: {list_id}", extra={'session_id': session_id})
        flash(trans('shopping_list_not_found', default='List not found.'), 'danger')
        return redirect(url_for('shopping.manage'))

    # Fetch items for the list
    list_items = list(db.shopping_items.find({'list_id': str(list_id)}))
    items = [{
        'id': str(item['_id']),
        'name': item.get('name', ''),
        'quantity': int(item.get('quantity', 1)),
        'price_raw': float(item.get('price', 0.0)),
        'unit': item.get('unit', 'piece'),
        'category': item.get('category', 'other'),
        'status': item.get('status', 'to_buy'),
        'store': item.get('store', 'Unknown'),
        'frequency': int(item.get('frequency', 7))
    } for item in list_items]

    # Calculate total cost for statistics
    total_cost = sum(item['price_raw'] * item['quantity'] for item in items)

    list_form = ShoppingListForm(data={'name': shopping_list['name'], 'budget': shopping_list['budget']})
    item_form = ShoppingItemsForm()

    if request.method == 'POST':
        action = request.form.get('action')
        logger.debug(f"Processing action: {action} with form data: {request.form.to_dict()}", extra={'session_id': session_id})

        if action == 'update_list':
            logger.debug(f"Attempting to update list: {list_id} with data: {request.form.to_dict()}", extra={'session_id': session_id})
            if list_form.validate_on_submit():
                try:
                    updated_data = {
                        'name': list_form.name.data.strip(),
                        'budget': float(list_form.budget.data),
                        'updated_at': datetime.utcnow()
                    }
                    result = db.shopping_lists.update_one(
                        {'_id': ObjectId(list_id), **filter_criteria},
                        {'$set': updated_data}
                    )
                    if result.modified_count > 0:
                        logger.info(f"List {list_id} updated successfully", extra={'session_id': session_id})
                        flash(trans('shopping_list_updated', default='Shopping list updated successfully!'), 'success')
                        get_shopping_lists.cache_clear()
                        return redirect(url_for('shopping.edit_list', list_id=list_id))
                    else:
                        logger.warning(f"No changes made to list {list_id}", extra={'session_id': session_id})
                        flash(trans('shopping_update_failed', default='Failed to update list.'), 'danger')
                except errors.WriteError as e:
                    logger.error(f"Failed to update list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                    flash(trans('shopping_update_error', default='Error updating list due to validation failure.'), 'danger')
                except Exception as e:
                    logger.error(f"Unexpected error updating list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                    flash(trans('shopping_update_error', default=f'Error updating list: {str(e)}'), 'danger')
            else:
                form_errors = {field: [trans(error, default=error) for error in field_errors] for field, field_errors in list_form.errors.items()}
                logger.debug(f"List form validation failed: {form_errors}", extra={'session_id': session_id})
                flash(trans('shopping_form_invalid', default='Invalid form data.'), 'danger')

        elif action == 'add_item':
            logger.debug(f"Attempting to add item to list: {list_id} with data: {request.form.to_dict()}", extra={'session_id': session_id})
            item_form = ShoppingItemsForm()
            if item_form.validate_on_submit():
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            new_item_data = {
                                '_id': ObjectId(),
                                'list_id': str(list_id),
                                'user_id': str(current_user.id),
                                'name': item_form.name.data.strip(),
                                'quantity': int(item_form.quantity.data),
                                'price': float(item_form.price.data),
                                'unit': item_form.unit.data,
                                'category': item_form.category.data or auto_categorize_item(item_form.name.data),
                                'status': item_form.status.data or 'to_buy',
                                'store': item_form.store.data.strip(),
                                'frequency': int(item_form.frequency.data),
                                'created_at': datetime.utcnow(),
                                'updated_at': datetime.utcnow()
                            }
                            logger.debug(f"Creating shopping item: {new_item_data}", extra={'session_id': session_id})
                            existing_items = db.shopping_items.count_documents(
                                {'list_id': str(list_id), 'name': {'$regex': f'^{new_item_data["name"].lower()}$', '$options': 'i'}},
                                session=mongo_session
                            )
                            if existing_items > 0:
                                logger.warning(f"Duplicate item name found: {new_item_data['name']}", extra={'session_id': session_id})
                                flash(trans('shopping_duplicate_item_name', default='Item name already exists in this list.'), 'danger')
                                return redirect(url_for('shopping.edit_list', list_id=list_id))
                            
                            created_item_id = create_shopping_item(db, new_item_data, mongo_session=mongo_session)
                            list_items = list(db.shopping_items.find({'list_id': str(list_id)}, session=mongo_session))
                            total_spent = sum(item['price'] * item['quantity'] for item in list_items)
                            db.shopping_lists.update_one(
                                {'_id': ObjectId(list_id)},
                                {'$set': {'total_spent': total_spent, 'updated_at': datetime.utcnow()}},
                                session=mongo_session
                            )
                            logger.info(f"Item {created_item_id} added to list {list_id}", extra={'session_id': session_id})
                            flash(trans('shopping_item_added', default='Item added successfully!'), 'success')
                            if total_spent > shopping_list['budget']:
                                flash(trans('shopping_over_budget', default='Warning: Total spent exceeds budget by ') + format_currency(total_spent - shopping_list['budget']) + '.', 'warning')
                            get_shopping_lists.cache_clear()
                            return redirect(url_for('shopping.edit_list', list_id=list_id))
                except errors.WriteError as e:
                    logger.error(f"Failed to add item to list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                    flash(trans('shopping_item_error', default='Error adding item due to validation failure.'), 'danger')
                except Exception as e:
                    logger.error(f"Unexpected error adding item to list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                    flash(trans('shopping_item_error', default=f'Error adding item: {str(e)}'), 'danger')
            else:
                form_errors = {field: [trans(error, default=error) for error in field_errors] for field, field_errors in item_form.errors.items()}
                logger.debug(f"Item form validation failed: {form_errors}", extra={'session_id': session_id})
                flash(trans('shopping_form_invalid', default='Invalid form data.'), 'danger')

        elif action == 'update_item':
            item_id = request.form.get('item_id')
            logger.debug(f"Attempting to update item {item_id} in list {list_id} with data: {request.form.to_dict()}", extra={'session_id': session_id})
            if not ObjectId.is_valid(item_id):
                logger.error(f"Invalid item ID: {item_id}", extra={'session_id': session_id})
                flash(trans('shopping_invalid_item_id', default='Invalid item ID.'), 'danger')
                return redirect(url_for('shopping.edit_list', list_id=list_id))
            item_form = ShoppingItemsForm()
            if item_form.validate_on_submit():
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            existing_item = db.shopping_items.find_one({'_id': ObjectId(item_id), 'list_id': str(list_id)}, session=mongo_session)
                            if not existing_item:
                                logger.error(f"Item not found: {item_id}", extra={'session_id': session_id})
                                flash(trans('shopping_item_not_found', default='Item not found.'), 'danger')
                                return redirect(url_for('shopping.edit_list', list_id=list_id))
                            updated_item_data = {
                                'name': item_form.name.data.strip(),
                                'quantity': int(item_form.quantity.data),
                                'price': float(item_form.price.data),
                                'unit': item_form.unit.data,
                                'category': item_form.category.data or auto_categorize_item(item_form.name.data),
                                'status': item_form.status.data or 'to_buy',
                                'store': item_form.store.data.strip(),
                                'frequency': int(item_form.frequency.data),
                                'updated_at': datetime.utcnow()
                            }
                            logger.debug(f"Updating shopping item {item_id}: {updated_item_data}", extra={'session_id': session_id})
                            existing_items = db.shopping_items.count_documents(
                                {'list_id': str(list_id), 'name': {'$regex': f'^{updated_item_data["name"].lower()}$', '$options': 'i'}, '_id': {'$ne': ObjectId(item_id)}},
                                session=mongo_session
                            )
                            if existing_items > 0:
                                logger.warning(f"Duplicate item name found: {updated_item_data['name']}", extra={'session_id': session_id})
                                flash(trans('shopping_duplicate_item_name', default='Item name already exists in this list.'), 'danger')
                                return redirect(url_for('shopping.edit_list', list_id=list_id))
                            result = db.shopping_items.update_one(
                                {'_id': ObjectId(item_id), 'list_id': str(list_id), **filter_criteria},
                                {'$set': updated_item_data},
                                session=mongo_session
                            )
                            if result.modified_count > 0:
                                list_items = list(db.shopping_items.find({'list_id': str(list_id)}, session=mongo_session))
                                total_spent = sum(item['price'] * item['quantity'] for item in list_items)
                                db.shopping_lists.update_one(
                                    {'_id': ObjectId(list_id)},
                                    {'$set': {'total_spent': total_spent, 'updated_at': datetime.utcnow()}},
                                    session=mongo_session
                                )
                                logger.info(f"Item {item_id} updated successfully in list {list_id}", extra={'session_id': session_id})
                                flash(trans('shopping_item_updated', default='Item updated successfully!'), 'success')
                                if total_spent > shopping_list['budget']:
                                    flash(trans('shopping_over_budget', default='Warning: Total spent exceeds budget by ') + format_currency(total_spent - shopping_list['budget']) + '.', 'warning')
                                get_shopping_lists.cache_clear()
                                return redirect(url_for('shopping.edit_list', list_id=list_id))
                            else:
                                logger.warning(f"No changes made to item {item_id} in list {list_id}", extra={'session_id': session_id})
                                flash(trans('shopping_update_item_failed', default='Failed to update item.'), 'danger')
                except errors.WriteError as e:
                    logger.error(f"Failed to update item {item_id} in list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                    flash(trans('shopping_item_error', default='Error updating item due to validation failure.'), 'danger')
                except Exception as e:
                    logger.error(f"Unexpected error updating item {item_id} in list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                    flash(trans('shopping_item_error', default=f'Error updating item: {str(e)}'), 'danger')
            else:
                form_errors = {field: [trans(error, default=error) for error in field_errors] for field, field_errors in item_form.errors.items()}
                logger.debug(f"Item update form validation failed: {form_errors}", extra={'session_id': session_id})
                flash(trans('shopping_form_invalid', default='Invalid form data.'), 'danger')

        elif action == 'delete_item':
            item_id = request.form.get('item_id')
            logger.debug(f"Attempting to delete item {item_id} from list {list_id}", extra={'session_id': session_id})
            if not ObjectId.is_valid(item_id):
                logger.error(f"Invalid item ID: {item_id}", extra={'session_id': session_id})
                flash(trans('shopping_invalid_item_id', default='Invalid item ID.'), 'danger')
                return redirect(url_for('shopping.edit_list', list_id=list_id))
            try:
                with db.client.start_session() as mongo_session:
                    with mongo_session.start_transaction():
                        existing_item = db.shopping_items.find_one({'_id': ObjectId(item_id), 'list_id': str(list_id)}, session=mongo_session)
                        if not existing_item:
                            logger.error(f"Item not found: {item_id}", extra={'session_id': session_id})
                            flash(trans('shopping_item_not_found', default='Item not found.'), 'danger')
                            return redirect(url_for('shopping.edit_list', list_id=list_id))
                        result = db.shopping_items.delete_one(
                            {'_id': ObjectId(item_id), 'list_id': str(list_id), **filter_criteria},
                            session=mongo_session
                        )
                        if result.deleted_count > 0:
                            list_items = list(db.shopping_items.find({'list_id': str(list_id)}, session=mongo_session))
                            total_spent = sum(item['price'] * item['quantity'] for item in list_items)
                            db.shopping_lists.update_one(
                                {'_id': ObjectId(list_id)},
                                {'$set': {'total_spent': total_spent, 'updated_at': datetime.utcnow()}},
                                session=mongo_session
                            )
                            logger.info(f"Item {item_id} deleted successfully from list {list_id}", extra={'session_id': session_id})
                            flash(trans('shopping_item_deleted', default='Item deleted successfully!'), 'success')
                            get_shopping_lists.cache_clear()
                            return redirect(url_for('shopping.edit_list', list_id=list_id))
                        else:
                            logger.warning(f"No item deleted for ID {item_id} in list {list_id}", extra={'session_id': session_id})
                            flash(trans('shopping_delete_item_failed', default='Failed to delete item.'), 'danger')
            except errors.WriteError as e:
                logger.error(f"Failed to delete item {item_id} from list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                flash(trans('shopping_item_error', default='Error deleting item due to validation failure.'), 'danger')
            except Exception as e:
                logger.error(f"Unexpected error deleting item {item_id} from list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
                flash(trans('shopping_item_error', default=f'Error deleting item: {str(e)}'), 'danger')

        # Re-render the template with form errors if validation failed
        return render_template(
            'shopping/edit_list.html',
            form=list_form,
            list_form=list_form,
            item_form=item_form,
            list_id=list_id,
            shopping_list=shopping_list,
            items=items,
            total_cost=total_cost,
            tool_title=trans('shopping_edit_list', default='Edit Shopping List')
        )

    return render_template(
        'shopping/edit_list.html',
        form=list_form,
        list_form=list_form,
        item_form=item_form,
        list_id=list_id,
        shopping_list=shopping_list,
        items=items,
        total_cost=total_cost,
        tool_title=trans('shopping_edit_list', default='Edit Shopping List')
    )

@shopping_bp.route('/toggle_item_status', methods=['POST'])
@custom_login_required
@requires_role(['personal', 'admin'])
def toggle_item_status():
    """Toggle the status of a shopping item between 'to_buy' and 'bought'."""
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
        logger.debug(f"New session created with sid: {session['sid']}")
    session.permanent = True
    session.modified = True

    db = get_mongo_db()
    data = request.get_json()
    item_id = data.get('item_id')
    session_id = session.get('sid', 'no-session-id')

    if not ObjectId.is_valid(item_id):
        logger.error(f"Invalid item ID: {item_id}", extra={'session_id': session_id})
        return jsonify({'success': False, 'error': trans('shopping_invalid_item_id', default='Invalid item ID.')}), 400

    filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)}
    item = db.shopping_items.find_one({'_id': ObjectId(item_id), **filter_criteria})

    if not item:
        logger.error(f"Item not found: {item_id}", extra={'session_id': session_id})
        return jsonify({'success': False, 'error': trans('shopping_item_not_found', default='Item not found.')}), 404

    new_status = 'bought' if item.get('status') == 'to_buy' else 'to_buy'

    try:
        with db.client.start_session() as mongo_session:
            with mongo_session.start_transaction():
                logger.debug(f"Updating status for item {item_id} to {new_status}", extra={'session_id': session_id})
                result = db.shopping_items.update_one(
                    {'_id': ObjectId(item_id), **filter_criteria},
                    {'$set': {'status': new_status, 'updated_at': datetime.utcnow()}},
                    session=mongo_session
                )
                if result.modified_count > 0:
                    list_items = list(db.shopping_items.find({'list_id': item['list_id']}, session=mongo_session))
                    total_spent = sum(item['price'] * item['quantity'] for item in list_items)
                    db.shopping_lists.update_one(
                        {'_id': ObjectId(item['list_id'])},
                        {'$set': {'total_spent': total_spent, 'updated_at': datetime.utcnow()}},
                        session=mongo_session
                    )
                    logger.info(f"Item {item_id} status updated to {new_status}", extra={'session_id': session_id})
                    return jsonify({'success': True, 'message': trans('shopping_item_status_updated', default='Item status updated successfully!')})
                else:
                    logger.warning(f"No changes made to item {item_id} status", extra={'session_id': session_id})
                    return jsonify({'success': False, 'error': trans('shopping_update_item_failed', default='Failed to update item status.')}), 500
    except errors.WriteError as e:
        logger.error(f"Failed to toggle status for item {item_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
        return jsonify({'success': False, 'error': trans('shopping_item_error', default='Error updating item status due to validation failure.')}), 500
    except Exception as e:
        logger.error(f"Unexpected error toggling status for item {item_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
        return jsonify({'success': False, 'error': trans('shopping_item_error', default=f'Error updating item status: {str(e)}')}), 500

@shopping_bp.route('/delete_list', methods=['POST'])
@custom_login_required
@requires_role(['personal', 'admin'])
def delete_list():
    """Delete a shopping list and all its items."""
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
        logger.debug(f"New session created with sid: {session['sid']}")
    
    db = get_mongo_db()
    session_id = session.get('sid', 'no-session-id')
    
    try:
        data = request.get_json()
        list_id = data.get('list_id')
        
        if not ObjectId.is_valid(list_id):
            logger.error(f"Invalid list ID: {list_id}", extra={'session_id': session_id})
            return jsonify({'success': False, 'error': trans('shopping_invalid_list_id', default='Invalid list ID.')}), 400
        
        filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)}
        shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
        
        if not shopping_list:
            logger.error(f"List not found: {list_id}", extra={'session_id': session_id})
            return jsonify({'success': False, 'error': trans('shopping_list_not_found', default='List not found.')}), 404
        
        try:
            with db.client.start_session() as mongo_session:
                with mongo_session.start_transaction():
                    db.shopping_items.delete_many({'list_id': list_id}, session=mongo_session)
                    
                    result = db.shopping_lists.delete_one({'_id': ObjectId(list_id)}, session=mongo_session)
                    
                    if result.deleted_count > 0:
                        if current_user.is_authenticated and not is_admin():
                            if not deduct_ficore_credits(db, current_user.id, 1, 'delete_shopping_list', list_id, mongo_session):
                                logger.warning(f"Failed to deduct FC for deleting list {list_id} by user {current_user.id}", extra={'session_id': session_id})
                        
                        try:
                            log_tool_usage(
                                tool_name='shopping',
                                db=db,
                                user_id=current_user.id,
                                session_id=session_id,
                                action='delete_list'
                            )
                        except Exception as e:
                            logger.warning(f"Error logging delete activity: {str(e)}", extra={'session_id': session_id})
                        
                        logger.info(f"List {list_id} deleted successfully", extra={'session_id': session_id})
                        return jsonify({'success': True, 'message': trans('shopping_list_deleted', default='List deleted successfully!')})
                    else:
                        logger.warning(f"No list deleted for ID {list_id}", extra={'session_id': session_id})
                        return jsonify({'success': False, 'error': trans('shopping_delete_failed', default='Failed to delete list.')}), 500
        except errors.WriteError as e:
            logger.error(f"Failed to delete list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
            return jsonify({'success': False, 'error': trans('shopping_delete_error', default='Error deleting list due to validation failure.')}), 500
        except Exception as e:
            logger.error(f"Unexpected error deleting list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
            return jsonify({'success': False, 'error': trans('shopping_delete_error', default=f'Error deleting list: {str(e)}')}), 500
            
    except Exception as e:
        logger.error(f"Error processing delete list request: {str(e)}", exc_info=True, extra={'session_id': session_id})
        return jsonify({'success': False, 'error': trans('shopping_delete_error', default='Error deleting list.')}), 500

@shopping_bp.route('/export_pdf/<list_id>', methods=['GET'])
@custom_login_required
@requires_role(['personal', 'admin'])
def export_pdf(list_id):
    """Export shopping list to PDF with FC deduction."""
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
        logger.debug(f"New session created with sid: {session['sid']}")
    
    db = get_mongo_db()
    session_id = session.get('sid', 'no-session-id')
    
    try:
        if not ObjectId.is_valid(list_id):
            logger.error(f"Invalid list ID: {list_id}", extra={'session_id': session_id})
            flash(trans('shopping_invalid_list_id', default='Invalid list ID.'), 'danger')
            return redirect(url_for('shopping.manage'))
        
        if current_user.is_authenticated and not is_admin():
            if not check_ficore_credit_balance(required_amount=2, user_id=current_user.id):
                logger.warning(f"Insufficient credits for PDF export for user {current_user.id}", extra={'session_id': session_id})
                flash(trans('shopping_insufficient_credits_pdf', default='Insufficient credits for PDF export. PDF export costs 2 FC.'), 'danger')
                return redirect(url_for('shopping.manage'))
        
        filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)}
        shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
        
        if not shopping_list:
            logger.error(f"List not found: {list_id}", extra={'session_id': session_id})
            flash(trans('shopping_list_not_found', default='List not found.'), 'danger')
            return redirect(url_for('shopping.manage'))
        
        list_items = list(db.shopping_items.find({'list_id': list_id}))
        
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        
        draw_ficore_pdf_header(p, current_user, y_start=height - 50)
        
        p.setFont("Helvetica-Bold", 16)
        p.drawString(50, height - 120, f"Shopping List: {shopping_list.get('name', 'Untitled')}")
        
        p.setFont("Helvetica", 12)
        y = height - 150
        p.drawString(50, y, f"Budget: {format_currency(shopping_list.get('budget', 0))}")
        y -= 20
        p.drawString(50, y, f"Total Spent: {format_currency(shopping_list.get('total_spent', 0))}")
        y -= 20
        p.drawString(50, y, f"Created: {format_date(shopping_list.get('created_at'))}")
        y -= 40
        
        p.setFont("Helvetica-Bold", 10)
        p.drawString(50, y, "Item")
        p.drawString(200, y, "Qty")
        p.drawString(250, y, "Price")
        p.drawString(300, y, "Unit")
        p.drawString(350, y, "Category")
        p.drawString(450, y, "Status")
        y -= 20
        
        p.setFont("Helvetica", 9)
        for item in list_items:
            if y < 50:
                p.showPage()
                draw_ficore_pdf_header(p, current_user, y_start=height - 50)
                y = height - 120
                p.setFont("Helvetica-Bold", 10)
                p.drawString(50, y, "Item")
                p.drawString(200, y, "Qty")
                p.drawString(250, y, "Price")
                p.drawString(300, y, "Unit")
                p.drawString(350, y, "Category")
                p.drawString(450, y, "Status")
                y -= 20
                p.setFont("Helvetica", 9)
            
            p.drawString(50, y, item.get('name', '')[:20])
            p.drawString(200, y, str(item.get('quantity', 1)))
            p.drawString(250, y, format_currency(item.get('price', 0)))
            p.drawString(300, y, item.get('unit', 'piece'))
            p.drawString(350, y, item.get('category', 'other'))
            p.drawString(450, y, item.get('status', 'to_buy'))
            y -= 15
        
        p.save()
        buffer.seek(0)
        
        if current_user.is_authenticated and not is_admin():
            if not deduct_ficore_credits(db, current_user.id, 2, 'export_shopping_list_pdf', list_id):
                logger.warning(f"Failed to deduct credits for PDF export for list {list_id} by user {current_user.id}", extra={'session_id': session_id})
                flash(trans('shopping_credit_deduction_failed', default='Failed to deduct credits for PDF export.'), 'danger')
                return redirect(url_for('shopping.manage'))
        
        logger.info(f"PDF exported successfully for list {list_id}", extra={'session_id': session_id})
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename=shopping_list_{shopping_list.get("name", "list")}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.pdf'}
        )
        
    except Exception as e:
        logger.error(f"Error exporting shopping list PDF for list {list_id}: {str(e)}", exc_info=True, extra={'session_id': session_id})
        flash(trans('shopping_pdf_error', default='Error generating PDF report.'), 'danger')
        return redirect(url_for('shopping.manage'))

@shopping_bp.errorhandler(CSRFError)
def handle_csrf_error(e):
    session_id = session.get('sid', 'no-session-id')
    logger.error(f"CSRF error on {request.path}: {e.description}", extra={'session_id': session_id})
    flash(trans('shopping_csrf_error', default='Form submission failed. Please refresh and try again.'), 'danger')
    return redirect(url_for('shopping.new', tab='create-list')), 404

def init_app(app):
    try:
        csrf.init_app(app)
        db = get_mongo_db()
        if db:
            db.shopping_lists.create_index([('user_id', 1), ('status', 1), ('updated_at', 1)])
    except Exception as e:
        logger.error(f"Error initializing shopping app: {str(e)}", exc_info=True)
