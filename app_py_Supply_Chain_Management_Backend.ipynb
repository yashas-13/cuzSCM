import sqlite3
import json
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__, static_folder='static')
DATABASE = 'database.db'

# --- Database Initialization and Connection ---

def get_db():
    """Establishes a database connection or returns the existing one."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Return rows as dict-like objects
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema from schema.sql."""
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        print("Database initialized successfully.")

def query_db(query, args=(), one=False):
    """Helper function to query the database."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# --- Authentication and Authorization ---

# In a real application, a more robust token system (like JWT) would be used.
# For this example, we'll use a simple session-like token mechanism.
# In a multi-user environment, these would be managed in a secure store.
# For simplicity, we'll store active tokens in memory (not production-ready).
active_tokens = {} # token: user_id

def generate_token(user_id):
    """Generates a simple token for the user."""
    token = os.urandom(24).hex() # Generates a random hex string as token
    active_tokens[token] = user_id
    return token

def get_user_from_token(token):
    """Retrieves user_id from an active token."""
    return active_tokens.get(token)

def login_required(f):
    """Decorator to check for a valid authorization token."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Authorization token missing!'}), 401
        
        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            return jsonify({'message': 'Token format invalid. Use "Bearer <token>"'}), 401

        user_id = get_user_from_token(token)
        if not user_id:
            return jsonify({'message': 'Invalid or expired token!'}), 401
        
        g.user_id = user_id # Make user_id available globally for the request
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """Decorator to check if the authenticated user has one of the required roles."""
    from functools import wraps
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user_id = g.user_id
            user = query_db("SELECT role FROM users WHERE id = ?", (user_id,), one=True)
            if user and user['role'] in roles:
                g.user_role = user['role'] # Make user_role available globally
                return f(*args, **kwargs)
            return jsonify({'message': 'Access denied: Insufficient permissions.'}), 403
        return decorated_function
    return decorator

# --- Utility for Audit Trail ---
def log_audit_event(user_id, action, entity_type=None, entity_id=None, details=None, ip_address=None):
    """Logs an event to the audit_trail table."""
    db = get_db()
    db.execute(
        "INSERT INTO audit_trail (user_id, action, entity_type, entity_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, action, entity_type, entity_id, json.dumps(details) if details else None, ip_address or request.remote_addr)
    )
    db.commit()


# --- Core Endpoints ---

@app.route('/login', methods=['POST'])
def login():
    """Handles user login and issues a token."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = query_db("SELECT id, username, password, role FROM users WHERE username = ?", (username,), one=True)

    if user and check_password_hash(user['password'], password):
        token = generate_token(user['id'])
        log_audit_event(user['id'], 'Login', details={'username': username, 'result': 'success'})
        return jsonify({'message': 'Login successful!', 'token': token, 'role': user['role'], 'user_id': user['id']})
    
    log_audit_event(None, 'Login Attempt Failed', details={'username': username, 'result': 'failed'})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Invalidates the user's token."""
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]
    if token in active_tokens:
        user_id = active_tokens.pop(token)
        log_audit_event(user_id, 'Logout')
        return jsonify({'message': 'Logged out successfully.'}), 200
    return jsonify({'message': 'Token not found or already logged out.'}), 400


# --- Manufacturer Specific APIs ---

@app.route('/api/manufacturer/users', methods=['GET', 'POST'])
@role_required(['manufacturer'])
def manufacturer_users():
    """Manages users by manufacturer."""
    db = get_db()
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        location = data.get('location') # Optional for CFA/Stockist

        if not username or not password or not role:
            return jsonify({'message': 'Username, password, and role are required!'}), 400
        
        # Check if role is valid for manufacturer to create
        if role not in ['cfa', 'super_stockist']:
            return jsonify({'message': 'Manufacturer can only create CFA or Super Stockist users.'}), 400

        try:
            hashed_password = generate_password_hash(password)
            cursor = db.execute("INSERT INTO users (username, password, role, location) VALUES (?, ?, ?, ?)",
                                (username, hashed_password, role, location))
            db.commit()
            new_user_id = cursor.lastrowid
            log_audit_event(g.user_id, 'User Created', 'User', new_user_id, {'username': username, 'role': role})
            return jsonify({'message': 'User created successfully', 'user_id': new_user_id}), 201
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Username already exists'}), 409
        except Exception as e:
            return jsonify({'message': f'Error creating user: {str(e)}'}), 500

    elif request.method == 'GET':
        users = query_db("SELECT id, username, role, location FROM users WHERE role IN ('cfa', 'super_stockist')")
        return jsonify([dict(u) for u in users])


@app.route('/api/manufacturer/users/<int:user_id>', methods=['PUT', 'DELETE'])
@role_required(['manufacturer'])
def manufacturer_user_detail(user_id):
    """Updates or deletes a specific user by manufacturer."""
    db = get_db()
    if request.method == 'PUT':
        data = request.get_json()
        # Allow updating role or location, but not username/password directly here
        role = data.get('role')
        location = data.get('location')

        if not role and not location:
            return jsonify({'message': 'No update data provided.'}), 400

        update_fields = []
        update_values = []
        if role:
            if role not in ['cfa', 'super_stockist']:
                return jsonify({'message': 'Manufacturer can only modify CFA or Super Stockist users.'}), 400
            update_fields.append("role = ?")
            update_values.append(role)
        if location:
            update_fields.append("location = ?")
            update_values.append(location)
        
        update_values.append(user_id) # Add user_id for WHERE clause

        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        db.execute(query, tuple(update_values))
        db.commit()
        log_audit_event(g.user_id, 'User Updated', 'User', user_id, {'updated_fields': data})
        return jsonify({'message': 'User updated successfully'})

    elif request.method == 'DELETE':
        # Prevent manufacturer from deleting themselves or other manufacturers
        target_user = query_db("SELECT role FROM users WHERE id = ?", (user_id,), one=True)
        if not target_user or target_user['role'] == 'manufacturer':
            return jsonify({'message': 'Cannot delete this user type.'}), 403

        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        log_audit_event(g.user_id, 'User Deleted', 'User', user_id)
        return jsonify({'message': 'User deleted successfully'})


@app.route('/api/manufacturer/products', methods=['GET', 'POST'])
@role_required(['manufacturer'])
def manufacturer_products():
    """Manages product master data by manufacturer."""
    db = get_db()
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        description = data.get('description')
        hsn = data.get('hsn')
        gst_percent = data.get('gst')
        composition = data.get('composition')
        category = data.get('category')

        if not name:
            return jsonify({'message': 'Product name is required!'}), 400
        
        try:
            cursor = db.execute(
                "INSERT INTO products (name, description, hsn, gst_percent, composition, category) VALUES (?, ?, ?, ?, ?, ?)",
                (name, description, hsn, gst_percent, composition, category)
            )
            db.commit()
            new_product_id = cursor.lastrowid
            log_audit_event(g.user_id, 'Product Created', 'Product', new_product_id, {'name': name})
            return jsonify({'message': 'Product added successfully', 'id': new_product_id}), 201
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Product with this name already exists'}), 409
        except Exception as e:
            return jsonify({'message': f'Error adding product: {str(e)}'}), 500

    elif request.method == 'GET':
        products = query_db("SELECT * FROM products")
        return jsonify([dict(p) for p in products])

@app.route('/api/manufacturer/products/<int:product_id>', methods=['PUT', 'DELETE'])
@role_required(['manufacturer'])
def manufacturer_product_detail(product_id):
    """Updates or deletes a specific product by manufacturer."""
    db = get_db()
    if request.method == 'PUT':
        data = request.get_json()
        name = data.get('name')
        description = data.get('description')
        hsn = data.get('hsn')
        gst_percent = data.get('gst')
        composition = data.get('composition')
        category = data.get('category')

        update_fields = []
        update_values = []
        if name:
            update_fields.append("name = ?")
            update_values.append(name)
        if description:
            update_fields.append("description = ?")
            update_values.append(description)
        if hsn:
            update_fields.append("hsn = ?")
            update_values.append(hsn)
        if gst_percent is not None:
            update_fields.append("gst_percent = ?")
            update_values.append(gst_percent)
        if composition:
            update_fields.append("composition = ?")
            update_values.append(composition)
        if category:
            update_fields.append("category = ?")
            update_values.append(category)

        if not update_fields:
            return jsonify({'message': 'No update data provided.'}), 400
        
        update_values.append(product_id)
        query = f"UPDATE products SET {', '.join(update_fields)} WHERE id = ?"
        db.execute(query, tuple(update_values))
        db.commit()
        log_audit_event(g.user_id, 'Product Updated', 'Product', product_id, {'updated_fields': data})
        return jsonify({'message': 'Product updated successfully'})

    elif request.method == 'DELETE':
        db.execute("DELETE FROM products WHERE id = ?", (product_id,))
        db.commit()
        log_audit_event(g.user_id, 'Product Deleted', 'Product', product_id)
        return jsonify({'message': 'Product deleted successfully'})


@app.route('/api/manufacturer/batches', methods=['GET', 'POST'])
@role_required(['manufacturer'])
def manufacturer_batches():
    """Manages product batches by manufacturer."""
    db = get_db()
    if request.method == 'POST':
        data = request.get_json()
        product_id = data.get('product_id')
        batch_no = data.get('batch_no')
        mfg_date = data.get('mfg_date')
        exp_date = data.get('exp_date')
        mrp = data.get('mrp')
        quantity = data.get('quantity')

        if not all([product_id, batch_no, quantity is not None]):
            return jsonify({'message': 'Product ID, Batch No, and Quantity are required!'}), 400
        
        try:
            # Insert into batches table
            cursor = db.execute(
                "INSERT INTO batches (product_id, batch_no, mfg_date, exp_date, mrp, initial_quantity) VALUES (?, ?, ?, ?, ?, ?)",
                (product_id, batch_no, mfg_date, exp_date, mrp, quantity)
            )
            db.commit()
            new_batch_id = cursor.lastrowid

            # Add initial stock to manufacturer's inventory
            manufacturer_user = query_db("SELECT id FROM users WHERE role = 'manufacturer'", one=True)
            if manufacturer_user:
                db.execute(
                    "INSERT INTO inventory (product_id, batch_id, location_type, location_user_id, quantity) VALUES (?, ?, ?, ?, ?)",
                    (product_id, new_batch_id, 'manufacturer', manufacturer_user['id'], quantity)
                )
                db.commit()
            
            log_audit_event(g.user_id, 'Batch Created & Stocked', 'Batch', new_batch_id, {'batch_no': batch_no, 'product_id': product_id, 'quantity': quantity})
            return jsonify({'message': 'Batch added and stock updated successfully', 'id': new_batch_id}), 201
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Batch number already exists'}), 409
        except Exception as e:
            return jsonify({'message': f'Error adding batch: {str(e)}'}), 500

    elif request.method == 'GET':
        batches = query_db("SELECT b.*, p.name as product_name FROM batches b JOIN products p ON b.product_id = p.id")
        return jsonify([dict(b) for b in batches])

@app.route('/api/manufacturer/batches/<int:batch_id>', methods=['PUT', 'DELETE'])
@role_required(['manufacturer'])
def manufacturer_batch_detail(batch_id):
    """Updates or deletes a specific batch by manufacturer."""
    db = get_db()
    if request.method == 'PUT':
        data = request.get_json()
        product_id = data.get('product_id')
        batch_no = data.get('batch_no')
        mfg_date = data.get('mfg_date')
        exp_date = data.get('exp_date')
        mrp = data.get('mrp')
        quantity = data.get('quantity') # This would typically be initial_quantity, not current stock

        update_fields = []
        update_values = []
        if product_id:
            update_fields.append("product_id = ?")
            update_values.append(product_id)
        if batch_no:
            update_fields.append("batch_no = ?")
            update_values.append(batch_no)
        if mfg_date:
            update_fields.append("mfg_date = ?")
            update_values.append(mfg_date)
        if exp_date:
            update_fields.append("exp_date = ?")
            update_values.append(exp_date)
        if mrp is not None:
            update_fields.append("mrp = ?")
            update_values.append(mrp)
        if quantity is not None:
            # For updating initial_quantity, not current inventory
            update_fields.append("initial_quantity = ?")
            update_values.append(quantity)

        if not update_fields:
            return jsonify({'message': 'No update data provided.'}), 400
        
        update_values.append(batch_id)
        query = f"UPDATE batches SET {', '.join(update_fields)} WHERE id = ?"
        db.execute(query, tuple(update_values))
        db.commit()
        log_audit_event(g.user_id, 'Batch Updated', 'Batch', batch_id, {'updated_fields': data})
        return jsonify({'message': 'Batch updated successfully'})

    elif request.method == 'DELETE':
        # Before deleting batch, ensure no inventory or orders depend on it
        # For simplicity, we'll allow delete, but in a real app, this needs careful CASCADE or prevention.
        db.execute("DELETE FROM batches WHERE id = ?", (batch_id,))
        db.commit()
        log_audit_event(g.user_id, 'Batch Deleted', 'Batch', batch_id)
        return jsonify({'message': 'Batch deleted successfully'})

@app.route('/api/manufacturer/pack-configs', methods=['GET', 'POST'])
@role_required(['manufacturer'])
def manufacturer_pack_configs():
    """Manages pack configurations by manufacturer."""
    db = get_db()
    if request.method == 'POST':
        data = request.get_json()
        product_id = data.get('product_id')
        pack_type = data.get('pack_type')
        units_per_pack = data.get('units_per_pack')
        dimensions = data.get('dimensions')

        if not all([product_id, pack_type]):
            return jsonify({'message': 'Product ID and Pack Type are required!'}), 400
        
        try:
            cursor = db.execute(
                "INSERT INTO pack_configurations (product_id, pack_type, units_per_pack, dimensions) VALUES (?, ?, ?, ?)",
                (product_id, pack_type, units_per_pack, dimensions)
            )
            db.commit()
            new_config_id = cursor.lastrowid
            log_audit_event(g.user_id, 'Pack Config Created', 'PackConfig', new_config_id, {'pack_type': pack_type, 'product_id': product_id})
            return jsonify({'message': 'Pack configuration added successfully', 'id': new_config_id}), 201
        except Exception as e:
            return jsonify({'message': f'Error adding pack configuration: {str(e)}'}), 500

    elif request.method == 'GET':
        configs = query_db("SELECT pc.*, p.name as product_name FROM pack_configurations pc JOIN products p ON pc.product_id = p.id")
        return jsonify([dict(c) for c in configs])

@app.route('/api/manufacturer/pack-configs/<int:config_id>', methods=['PUT', 'DELETE'])
@role_required(['manufacturer'])
def manufacturer_pack_config_detail(config_id):
    """Updates or deletes a specific pack configuration by manufacturer."""
    db = get_db()
    if request.method == 'PUT':
        data = request.get_json()
        product_id = data.get('product_id')
        pack_type = data.get('pack_type')
        units_per_pack = data.get('units_per_pack')
        dimensions = data.get('dimensions')

        update_fields = []
        update_values = []
        if product_id:
            update_fields.append("product_id = ?")
            update_values.append(product_id)
        if pack_type:
            update_fields.append("pack_type = ?")
            update_values.append(pack_type)
        if units_per_pack:
            update_fields.append("units_per_pack = ?")
            update_values.append(units_per_pack)
        if dimensions:
            update_fields.append("dimensions = ?")
            update_values.append(dimensions)

        if not update_fields:
            return jsonify({'message': 'No update data provided.'}), 400
        
        update_values.append(config_id)
        query = f"UPDATE pack_configurations SET {', '.join(update_fields)} WHERE id = ?"
        db.execute(query, tuple(update_values))
        db.commit()
        log_audit_event(g.user_id, 'Pack Config Updated', 'PackConfig', config_id, {'updated_fields': data})
        return jsonify({'message': 'Pack configuration updated successfully'})

    elif request.method == 'DELETE':
        db.execute("DELETE FROM pack_configurations WHERE id = ?", (config_id,))
        db.commit()
        log_audit_event(g.user_id, 'Pack Config Deleted', 'PackConfig', config_id)
        return jsonify({'message': 'Pack configuration deleted successfully'})


@app.route('/api/manufacturer/pricing', methods=['GET', 'POST'])
@role_required(['manufacturer'])
def manufacturer_pricing():
    """Manages pricing catalogs by manufacturer."""
    db = get_db()
    if request.method == 'POST':
        data = request.get_json()
        product_id = data.get('product_id')
        state_region = data.get('state_region')
        ptr = data.get('ptr')
        pts = data.get('pts')
        effective_date = data.get('effective_date')

        if not all([product_id, state_region, ptr, pts, effective_date]):
            return jsonify({'message': 'All pricing fields are required!'}), 400
        
        try:
            cursor = db.execute(
                "INSERT INTO pricing (product_id, state_region, ptr, pts, effective_date) VALUES (?, ?, ?, ?, ?)",
                (product_id, state_region, ptr, pts, effective_date)
            )
            db.commit()
            new_price_id = cursor.lastrowid
            log_audit_event(g.user_id, 'Pricing Rule Created', 'Pricing', new_price_id, {'product_id': product_id, 'region': state_region})
            return jsonify({'message': 'Pricing rule added successfully', 'id': new_price_id}), 201
        except Exception as e:
            return jsonify({'message': f'Error adding pricing rule: {str(e)}'}), 500

    elif request.method == 'GET':
        region = request.args.get('state_region')
        query = "SELECT p.*, prod.name as product_name FROM pricing p JOIN products prod ON p.product_id = prod.id"
        args = ()
        if region and region != 'all':
            query += " WHERE state_region = ?"
            args = (region,)
        pricing_data = query_db(query, args)
        return jsonify([dict(p) for p in pricing_data])

@app.route('/api/manufacturer/pricing/<int:price_id>', methods=['PUT', 'DELETE'])
@role_required(['manufacturer'])
def manufacturer_pricing_detail(price_id):
    """Updates or deletes a specific pricing rule by manufacturer."""
    db = get_db()
    if request.method == 'PUT':
        data = request.get_json()
        product_id = data.get('product_id')
        state_region = data.get('state_region')
        ptr = data.get('ptr')
        pts = data.get('pts')
        effective_date = data.get('effective_date')

        update_fields = []
        update_values = []
        if product_id:
            update_fields.append("product_id = ?")
            update_values.append(product_id)
        if state_region:
            update_fields.append("state_region = ?")
            update_values.append(state_region)
        if ptr is not None:
            update_fields.append("ptr = ?")
            update_values.append(ptr)
        if pts is not None:
            update_fields.append("pts = ?")
            update_values.append(pts)
        if effective_date:
            update_fields.append("effective_date = ?")
            update_values.append(effective_date)

        if not update_fields:
            return jsonify({'message': 'No update data provided.'}), 400
        
        update_values.append(price_id)
        query = f"UPDATE pricing SET {', '.join(update_fields)} WHERE id = ?"
        db.execute(query, tuple(update_values))
        db.commit()
        log_audit_event(g.user_id, 'Pricing Rule Updated', 'Pricing', price_id, {'updated_fields': data})
        return jsonify({'message': 'Pricing rule updated successfully'})

    elif request.method == 'DELETE':
        db.execute("DELETE FROM pricing WHERE id = ?", (price_id,))
        db.commit()
        log_audit_event(g.user_id, 'Pricing Rule Deleted', 'Pricing', price_id)
        return jsonify({'message': 'Pricing rule deleted successfully'})


@app.route('/api/manufacturer/orders/cfa', methods=['GET'])
@role_required(['manufacturer'])
def manufacturer_cfa_orders():
    """Manufacturer views orders placed by CFAs."""
    status = request.args.get('status', 'pending') # Default to pending orders
    orders = query_db("""
        SELECT o.id, p.name as product_name, b.batch_no, o.quantity, o.order_date, o.status,
               from_user.username as from_cfa_username, from_user.location as from_cfa_location
        FROM orders o
        JOIN products p ON o.product_id = p.id
        LEFT JOIN batches b ON o.batch_id = b.id
        JOIN users from_user ON o.from_user_id = from_user.id
        WHERE o.to_user_id = (SELECT id FROM users WHERE role = 'manufacturer' LIMIT 1)
          AND from_user.role = 'cfa' AND o.status = ?
    """, (status,))
    return jsonify([dict(o) for o in orders])


@app.route('/api/manufacturer/orders/<int:order_id>/approve', methods=['POST'])
@role_required(['manufacturer'])
def manufacturer_approve_order(order_id):
    """Manufacturer approves a CFA order, updates inventory."""
    db = get_db()
    order = query_db("SELECT * FROM orders WHERE id = ? AND status = 'pending'", (order_id,), one=True)
    if not order:
        return jsonify({'message': 'Order not found or not pending.'}), 404
    
    # Check manufacturer's own stock
    manufacturer_id = query_db("SELECT id FROM users WHERE role = 'manufacturer' LIMIT 1", one=True)['id']
    mfg_inventory = query_db(
        "SELECT * FROM inventory WHERE product_id = ? AND batch_id = ? AND location_user_id = ?",
        (order['product_id'], order['batch_id'], manufacturer_id), one=True
    )
    if not mfg_inventory or mfg_inventory['quantity'] < order['quantity']:
        return jsonify({'message': 'Insufficient stock at Manufacturer for this order.'}), 400

    try:
        # 1. Update order status to 'approved' and set dispatch date
        db.execute("UPDATE orders SET status = 'approved', dispatch_date = ? WHERE id = ?",
                   (datetime.now().isoformat(), order_id))
        
        # 2. Decrease Manufacturer's inventory
        new_mfg_quantity = mfg_inventory['quantity'] - order['quantity']
        db.execute("UPDATE inventory SET quantity = ?, last_updated = ? WHERE id = ?",
                   (new_mfg_quantity, datetime.now().isoformat(), mfg_inventory['id']))

        # 3. Increase CFA's inventory (or create new entry if it doesn't exist for this batch/product)
        cfa_inventory = query_db(
            "SELECT * FROM inventory WHERE product_id = ? AND batch_id = ? AND location_user_id = ?",
            (order['from_user_id'], order['batch_id'], order['to_user_id']), one=True # Should be from_user_id (CFA)
        )
        if cfa_inventory:
            new_cfa_quantity = cfa_inventory['quantity'] + order['quantity']
            db.execute("UPDATE inventory SET quantity = ?, last_updated = ? WHERE id = ?",
                       (new_cfa_quantity, datetime.now().isoformat(), cfa_inventory['id']))
        else:
            db.execute(
                "INSERT INTO inventory (product_id, batch_id, location_type, location_user_id, quantity) VALUES (?, ?, ?, ?, ?)",
                (order['product_id'], order['batch_id'], 'cfa', order['from_user_id'], order['quantity']) # from_user_id is the CFA receiving
            )
        db.commit()
        log_audit_event(g.user_id, 'Order Approved & Dispatched (Mfr)', 'Order', order_id, {'order_quantity': order['quantity'], 'to_cfa_id': order['from_user_id']})
        return jsonify({'message': 'Order approved and stock transferred successfully.'}), 200
    except Exception as e:
        db.rollback()
        return jsonify({'message': f'Error approving order: {str(e)}'}), 500


@app.route('/api/manufacturer/stock-visibility', methods=['GET'])
@role_required(['manufacturer'])
def manufacturer_stock_visibility():
    """Provides full stock visibility across all locations for manufacturer."""
    # This query joins inventory with products and batches to get full details
    stock_data = query_db("""
        SELECT i.id, p.name as product_name, b.batch_no, i.quantity, b.exp_date, i.last_updated,
               u.username as location_user_name, u.role as location_type, u.location
        FROM inventory i
        JOIN products p ON i.product_id = p.id
        JOIN batches b ON i.batch_id = b.id
        JOIN users u ON i.location_user_id = u.id
    """)
    return jsonify([dict(s) for s in stock_data])

@app.route('/api/manufacturer/audit-trail', methods=['GET'])
@role_required(['manufacturer'])
def manufacturer_audit_trail():
    """Retrieves audit logs for manufacturer."""
    # Manufacturer can view all audit logs
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    user_filter = request.args.get('user_id')
    action_filter = request.args.get('action')

    query = """
        SELECT a.timestamp, u.username as user, u.role, a.action, a.entity_type, a.entity_id, a.details, a.ip_address
        FROM audit_trail a
        JOIN users u ON a.user_id = u.id
        WHERE 1=1
    """
    params = []

    if start_date:
        query += " AND a.timestamp >= ?"
        params.append(start_date)
    if end_date:
        query += " AND a.timestamp <= ?"
        params.append(end_date)
    if user_filter:
        query += " AND u.id = ?"
        params.append(user_filter)
    if action_filter:
        query += " AND a.action LIKE ?"
        params.append(f"%{action_filter}%")
    
    query += " ORDER BY a.timestamp DESC"

    logs = query_db(query, tuple(params))
    # Parse JSON details if present
    for log in logs:
        if log['details']:
            log['details'] = json.loads(log['details'])
    return jsonify([dict(l) for l in logs])

@app.route('/api/manufacturer/recall', methods=['POST'])
@role_required(['manufacturer'])
def manufacturer_recall_trigger():
    """Initiates a batch-level recall."""
    db = get_db()
    data = request.get_json()
    batch_no = data.get('batch_no')
    reason = data.get('reason')
    scope = data.get('scope', 'all') # 'all' or 'select' (for specific stockists, not implemented in this version)

    if not batch_no or not reason:
        return jsonify({'message': 'Batch number and reason for recall are required!'}), 400

    batch = query_db("SELECT id, product_id FROM batches WHERE batch_no = ?", (batch_no,), one=True)
    if not batch:
        return jsonify({'message': 'Batch not found.'}), 404

    try:
        # Mark all inventory items of this batch as recalled
        db.execute("UPDATE inventory SET quantity = 0, last_updated = ?, status = 'recalled' WHERE batch_id = ?",
                   (datetime.now().isoformat(), batch['id']))
        # Optionally, update relevant orders status or create new recall orders
        # For simplicity, we just log it and zero out inventory

        db.commit()
        log_audit_event(g.user_id, 'Recall Initiated', 'Batch', batch['id'], {'batch_no': batch_no, 'reason': reason, 'scope': scope})
        return jsonify({'message': f'Recall initiated for batch {batch_no}. All relevant stock marked.'}), 200
    except Exception as e:
        db.rollback()
        return jsonify({'message': f'Error initiating recall: {str(e)}'}), 500


# --- CFA Specific APIs (Placeholders - will be expanded later) ---

@app.route('/api/cfa/products', methods=['GET'])
@role_required(['cfa'])
def cfa_products():
    """CFA views product master data."""
    products = query_db("SELECT * FROM products")
    return jsonify([dict(p) for p in products])

@app.route('/api/cfa/batches', methods=['GET'])
@role_required(['cfa'])
def cfa_batches():
    """CFA views batch master data."""
    batches = query_db("SELECT b.*, p.name as product_name FROM batches b JOIN products p ON b.product_id = p.id")
    return jsonify([dict(b) for b in batches])

@app.route('/api/cfa/pack-configs', methods=['GET'])
@role_required(['cfa'])
def cfa_pack_configs():
    """CFA views pack configurations."""
    configs = query_db("SELECT pc.*, p.name as product_name FROM pack_configurations pc JOIN products p ON pc.product_id = p.id")
    return jsonify([dict(c) for c in configs])

@app.route('/api/cfa/pricing', methods=['GET'])
@role_required(['cfa'])
def cfa_pricing():
    """CFA views pricing catalog (can filter by their region if specified)."""
    user_location = query_db("SELECT location FROM users WHERE id = ?", (g.user_id,), one=True)['location']
    query = "SELECT p.*, prod.name as product_name FROM pricing p JOIN products prod ON p.product_id = prod.id WHERE state_region = ? OR state_region = 'All India'"
    pricing_data = query_db(query, (user_location,))
    return jsonify([dict(p) for p in pricing_data])

@app.route('/api/cfa/orders/super-stockist', methods=['GET', 'POST'])
@role_required(['cfa'])
def cfa_super_stockist_orders():
    """CFA manages incoming orders from Super Stockists."""
    db = get_db()
    if request.method == 'POST':
        # CFA approves/rejects a Super Stockist order
        data = request.get_json()
        order_id = data.get('order_id')
        action = data.get('action') # 'approve' or 'reject'

        order = query_db("SELECT * FROM orders WHERE id = ? AND to_user_id = ?", (order_id, g.user_id), one=True)
        if not order:
            return jsonify({'message': 'Order not found or you are not the recipient CFA.'}), 404
        if order['status'] != 'pending':
            return jsonify({'message': 'Order already processed.'}), 400

        if action == 'approve':
            # Check CFA's own stock
            cfa_inventory = query_db(
                "SELECT * FROM inventory WHERE product_id = ? AND batch_id = ? AND location_user_id = ?",
                (order['product_id'], order['batch_id'], g.user_id), one=True
            )
            if not cfa_inventory or cfa_inventory['quantity'] < order['quantity']:
                return jsonify({'message': 'Insufficient stock at CFA for this order.'}), 400

            try:
                # 1. Update order status to 'approved' and set dispatch date
                db.execute("UPDATE orders SET status = 'approved', dispatch_date = ? WHERE id = ?",
                           (datetime.now().isoformat(), order_id))
                
                # 2. Decrease CFA's inventory
                new_cfa_quantity = cfa_inventory['quantity'] - order['quantity']
                db.execute("UPDATE inventory SET quantity = ?, last_updated = ? WHERE id = ?",
                           (new_cfa_quantity, datetime.now().isoformat(), cfa_inventory['id']))

                # 3. Increase Super Stockist's inventory (or create new entry)
                stockist_inventory = query_db(
                    "SELECT * FROM inventory WHERE product_id = ? AND batch_id = ? AND location_user_id = ?",
                    (order['product_id'], order['batch_id'], order['from_user_id']), one=True # to_user_id is the Stockist receiving
                )
                if stockist_inventory:
                    new_stockist_quantity = stockist_inventory['quantity'] + order['quantity']
                    db.execute("UPDATE inventory SET quantity = ?, last_updated = ? WHERE id = ?",
                               (new_stockist_quantity, datetime.now().isoformat(), stockist_inventory['id']))
                else:
                    db.execute(
                        "INSERT INTO inventory (product_id, batch_id, location_type, location_user_id, quantity) VALUES (?, ?, ?, ?, ?)",
                        (order['product_id'], order['batch_id'], 'super_stockist', order['from_user_id'], order['quantity'])
                    )
                db.commit()
                log_audit_event(g.user_id, 'Order Approved (CFA)', 'Order', order_id, {'order_quantity': order['quantity'], 'to_stockist_id': order['from_user_id']})
                return jsonify({'message': 'Order approved and stock transferred successfully.'}), 200
            except Exception as e:
                db.rollback()
                return jsonify({'message': f'Error approving order: {str(e)}'}), 500
        
        elif action == 'reject':
            db.execute("UPDATE orders SET status = 'rejected' WHERE id = ?", (order_id,))
            db.commit()
            log_audit_event(g.user_id, 'Order Rejected (CFA)', 'Order', order_id)
            return jsonify({'message': 'Order rejected successfully.'}), 200
        else:
            return jsonify({'message': 'Invalid action.'}), 400

    elif request.method == 'GET':
        status = request.args.get('status', 'pending')
        orders = query_db("""
            SELECT o.id, p.name as product_name, b.batch_no, o.quantity, o.order_date, o.status,
                   from_user.username as from_stockist_username, from_user.location as from_stockist_location
            FROM orders o
            JOIN products p ON o.product_id = p.id
            LEFT JOIN batches b ON o.batch_id = b.id
            JOIN users from_user ON o.from_user_id = from_user.id
            WHERE o.to_user_id = ? AND from_user.role = 'super_stockist' AND o.status = ?
        """, (g.user_id, status))
        return jsonify([dict(o) for o in orders])

@app.route('/api/cfa/orders/manufacturer', methods=['GET', 'POST'])
@role_required(['cfa'])
def cfa_manufacturer_orders():
    """CFA places and views orders to Manufacturer."""
    db = get_db()
    manufacturer_user = query_db("SELECT id FROM users WHERE role = 'manufacturer' LIMIT 1", one=True)
    if not manufacturer_user:
        return jsonify({'message': 'Manufacturer user not found in system.'}), 500

    if request.method == 'POST':
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity')
        batch_id = data.get('batch_id') # Can be chosen by CFA if multiple batches available at Mfr, or determined by Mfr on approval

        if not all([product_id, quantity]):
            return jsonify({'message': 'Product ID and Quantity are required!'}), 400

        try:
            cursor = db.execute(
                "INSERT INTO orders (product_id, quantity, from_user_id, to_user_id, status, batch_id) VALUES (?, ?, ?, ?, ?, ?)",
                (product_id, quantity, g.user_id, manufacturer_user['id'], 'pending', batch_id)
            )
            db.commit()
            new_order_id = cursor.lastrowid
            log_audit_event(g.user_id, 'Order Placed (CFA to Mfr)', 'Order', new_order_id, {'product_id': product_id, 'quantity': quantity})
            return jsonify({'message': 'Order placed successfully to Manufacturer.', 'order_id': new_order_id}), 201
        except Exception as e:
            return jsonify({'message': f'Error placing order: {str(e)}'}), 500

    elif request.method == 'GET':
        orders = query_db("""
            SELECT o.id, p.name as product_name, b.batch_no, o.quantity, o.order_date, o.status,
                   to_user.username as to_manufacturer_username
            FROM orders o
            JOIN products p ON o.product_id = p.id
            LEFT JOIN batches b ON o.batch_id = b.id
            JOIN users to_user ON o.to_user_id = to_user.id
            WHERE o.from_user_id = ? AND to_user.role = 'manufacturer'
        """, (g.user_id,))
        return jsonify([dict(o) for o in orders])


@app.route('/api/cfa/my-stock', methods=['GET'])
@role_required(['cfa'])
def cfa_my_stock():
    """CFA views stock at their own location."""
    stock_data = query_db("""
        SELECT i.id, p.name as product_name, b.batch_no, i.quantity, b.exp_date, i.last_updated
        FROM inventory i
        JOIN products p ON i.product_id = p.id
        JOIN batches b ON i.batch_id = b.id
        WHERE i.location_user_id = ? AND i.location_type = 'cfa'
    """, (g.user_id,))
    return jsonify([dict(s) for s in stock_data])

@app.route('/api/cfa/stock/receive', methods=['POST'])
@role_required(['cfa'])
def cfa_receive_stock():
    """CFA records stock received from manufacturer."""
    db = get_db()
    data = request.get_json()
    product_id = data.get('product_id')
    batch_no = data.get('batch_no')
    quantity = data.get('quantity')
    exp_date = data.get('exp_date') # From form, might not match batch master exactly if input by hand

    if not all([product_id, batch_no, quantity is not None]):
        return jsonify({'message': 'Product ID, Batch No, and Quantity are required!'}), 400

    batch = query_db("SELECT id, product_id FROM batches WHERE batch_no = ?", (batch_no,), one=True)
    if not batch:
        return jsonify({'message': 'Batch not found in system. Please add batch master data first.'}), 404
    if batch['product_id'] != product_id:
        return jsonify({'message': 'Product ID does not match batch number.'}), 400

    try:
        # Check if inventory for this batch/product already exists for this CFA
        current_inventory = query_db(
            "SELECT id, quantity FROM inventory WHERE product_id = ? AND batch_id = ? AND location_user_id = ?",
            (product_id, batch['id'], g.user_id), one=True
        )

        if current_inventory:
            new_quantity = current_inventory['quantity'] + quantity
            db.execute("UPDATE inventory SET quantity = ?, last_updated = ? WHERE id = ?",
                       (new_quantity, datetime.now().isoformat(), current_inventory['id']))
        else:
            db.execute(
                "INSERT INTO inventory (product_id, batch_id, location_type, location_user_id, quantity, last_updated) VALUES (?, ?, ?, ?, ?, ?)",
                (product_id, batch['id'], 'cfa', g.user_id, quantity, datetime.now().isoformat())
            )
        db.commit()
        log_audit_event(g.user_id, 'Stock Received (CFA)', 'Inventory', batch['id'], {'product_id': product_id, 'batch_no': batch_no, 'quantity': quantity})
        return jsonify({'message': 'Stock received and updated successfully.'}), 200
    except Exception as e:
        db.rollback()
        return jsonify({'message': f'Error receiving stock: {str(e)}'}), 500

@app.route('/api/cfa/stock/dispatch', methods=['POST'])
@role_required(['cfa'])
def cfa_dispatch_stock():
    """CFA dispatches stock to a Super Stockist."""
    db = get_db()
    data = request.get_json()
    product_id = data.get('product_id')
    batch_no = data.get('batch_no')
    quantity = data.get('quantity')
    to_stockist_id = data.get('to_stockist_id')

    if not all([product_id, batch_no, quantity is not None, to_stockist_id]):
        return jsonify({'message': 'All dispatch fields are required!'}), 400

    batch = query_db("SELECT id, product_id FROM batches WHERE batch_no = ?", (batch_no,), one=True)
    if not batch:
        return jsonify({'message': 'Batch not found.'}), 404
    if batch['product_id'] != product_id:
        return jsonify({'message': 'Product ID does not match batch number.'}), 400

    stockist_user = query_db("SELECT id, role FROM users WHERE id = ? AND role = 'super_stockist'", (to_stockist_id,), one=True)
    if not stockist_user:
        return jsonify({'message': 'Recipient is not a valid Super Stockist.'}), 400

    # Check CFA's own stock for dispatch
    cfa_inventory = query_db(
        "SELECT id, quantity FROM inventory WHERE product_id = ? AND batch_id = ? AND location_user_id = ?",
        (product_id, batch['id'], g.user_id), one=True
    )

    if not cfa_inventory or cfa_inventory['quantity'] < quantity:
        return jsonify({'message': 'Insufficient stock at your CFA location for this dispatch.'}), 400

    try:
        # 1. Decrease CFA's inventory
        new_cfa_quantity = cfa_inventory['quantity'] - quantity
        db.execute("UPDATE inventory SET quantity = ?, last_updated = ? WHERE id = ?",
                   (new_cfa_quantity, datetime.now().isoformat(), cfa_inventory['id']))

        # 2. Increase Super Stockist's inventory (or create new entry)
        stockist_inventory = query_db(
            "SELECT id, quantity FROM inventory WHERE product_id = ? AND batch_id = ? AND location_user_id = ?",
            (product_id, batch['id'], to_stockist_id), one=True
        )

        if stockist_inventory:
            new_stockist_quantity = stockist_inventory['quantity'] + quantity
            db.execute("UPDATE inventory SET quantity = ?, last_updated = ? WHERE id = ?",
                       (new_stockist_quantity, datetime.now().isoformat(), stockist_inventory['id']))
        else:
            db.execute(
                "INSERT INTO inventory (product_id, batch_id, location_type, location_user_id, quantity, last_updated) VALUES (?, ?, ?, ?, ?, ?)",
                (product_id, batch['id'], 'super_stockist', to_stockist_id, quantity, datetime.now().isoformat())
            )
        
        db.commit()
        log_audit_event(g.user_id, 'Stock Dispatched (CFA)', 'Inventory', batch['id'], {'product_id': product_id, 'batch_no': batch_no, 'quantity': quantity, 'to_stockist': to_stockist_id})
        return jsonify({'message': 'Stock dispatched successfully to Super Stockist.'}), 200
    except Exception as e:
        db.rollback()
        return jsonify({'message': f'Error dispatching stock: {str(e)}'}), 500


@app.route('/api/cfa/downstream-stock', methods=['GET'])
@role_required(['cfa'])
def cfa_downstream_stock_visibility():
    """CFA views stock of associated Super Stockists."""
    # Find all Super Stockists linked to this CFA
    stockists = query_db("SELECT id FROM users WHERE cfa_id = ?", (g.user_id,))
    stockist_ids = [s['id'] for s in stockists]

    if not stockist_ids:
        return jsonify([]) # No downstream stockists found

    # Query inventory for these stockists
    # Using a placeholder for IN clause for multiple IDs
    placeholders = ','.join('?' for _ in stockist_ids)
    query = f"""
        SELECT i.id, p.name as product_name, b.batch_no, i.quantity, b.exp_date, i.last_updated,
               u.username as super_stockist_name, u.location as super_stockist_location
        FROM inventory i
        JOIN products p ON i.product_id = p.id
        JOIN batches b ON i.batch_id = b.id
        JOIN users u ON i.location_user_id = u.id
        WHERE i.location_user_id IN ({placeholders}) AND i.location_type = 'super_stockist'
    """
    stock_data = query_db(query, tuple(stockist_ids))
    return jsonify([dict(s) for s in stock_data])

@app.route('/api/cfa/audit-trail', methods=['GET'])
@role_required(['cfa'])
def cfa_audit_trail():
    """Retrieves audit logs for the current CFA user."""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    action_filter = request.args.get('action')

    query = """
        SELECT a.timestamp, u.username as user, u.role, a.action, a.entity_type, a.entity_id, a.details, a.ip_address
        FROM audit_trail a
        JOIN users u ON a.user_id = u.id
        WHERE u.id = ?
    """
    params = [g.user_id]

    if start_date:
        query += " AND a.timestamp >= ?"
        params.append(start_date)
    if end_date:
        query += " AND a.timestamp <= ?"
        params.append(end_date)
    if action_filter:
        query += " AND a.action LIKE ?"
        params.append(f"%{action_filter}%")
    
    query += " ORDER BY a.timestamp DESC"

    logs = query_db(query, tuple(params))
    for log in logs:
        if log['details']:
            log['details'] = json.loads(log['details'])
    return jsonify([dict(l) for l in logs])

# --- Super Stockist Specific APIs (Placeholders - will be expanded later) ---

@app.route('/api/stockist/products', methods=['GET'])
@role_required(['super_stockist'])
def stockist_products():
    """Super Stockist views product catalog."""
    products = query_db("SELECT * FROM products")
    return jsonify([dict(p) for p in products])

@app.route('/api/stockist/batches', methods=['GET'])
@role_required(['super_stockist'])
def stockist_batches():
    """Super Stockist views batch information (global or relevant to their CFA)."""
    batches = query_db("SELECT b.*, p.name as product_name FROM batches b JOIN products p ON b.product_id = p.id")
    return jsonify([dict(b) for b in batches])

@app.route('/api/stockist/pricing', methods=['GET'])
@role_required(['super_stockist'])
def stockist_pricing():
    """Super Stockist views pricing catalog relevant to their region."""
    user_location = query_db("SELECT location FROM users WHERE id = ?", (g.user_id,), one=True)['location']
    query = "SELECT p.*, prod.name as product_name FROM pricing p JOIN products prod ON p.product_id = prod.id WHERE state_region = ? OR state_region = 'All India'"
    pricing_data = query_db(query, (user_location,))
    return jsonify([dict(p) for p in pricing_data])

@app.route('/api/stockist/orders/cfa', methods=['GET', 'POST'])
@role_required(['super_stockist'])
def stockist_cfa_orders():
    """Super Stockist places and views orders to their CFA."""
    db = get_db()
    
    # Get the CFA associated with this Super Stockist
    stockist_info = query_db("SELECT cfa_id FROM users WHERE id = ?", (g.user_id,), one=True)
    if not stockist_info or not stockist_info['cfa_id']:
        return jsonify({'message': 'No CFA assigned to this Super Stockist.'}), 400
    
    cfa_user_id = stockist_info['cfa_id']

    if request.method == 'POST':
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity')
        # Super Stockist doesn't pick batch; CFA will assign it on approval/dispatch

        if not all([product_id, quantity]):
            return jsonify({'message': 'Product ID and Quantity are required!'}), 400

        try:
            cursor = db.execute(
                "INSERT INTO orders (product_id, quantity, from_user_id, to_user_id, status) VALUES (?, ?, ?, ?, ?)",
                (product_id, quantity, g.user_id, cfa_user_id, 'pending')
            )
            db.commit()
            new_order_id = cursor.lastrowid
            log_audit_event(g.user_id, 'Order Placed (Stockist to CFA)', 'Order', new_order_id, {'product_id': product_id, 'quantity': quantity})
            return jsonify({'message': 'Order placed successfully to CFA.', 'order_id': new_order_id}), 201
        except Exception as e:
            return jsonify({'message': f'Error placing order: {str(e)}'}), 500

    elif request.method == 'GET':
        orders = query_db("""
            SELECT o.id, p.name as product_name, b.batch_no, o.quantity, o.order_date, o.status,
                   to_user.username as to_cfa_username
            FROM orders o
            JOIN products p ON o.product_id = p.id
            LEFT JOIN batches b ON o.batch_id = b.id
            JOIN users to_user ON o.to_user_id = to_user.id
            WHERE o.from_user_id = ? AND to_user.role = 'cfa'
        """, (g.user_id,))
        return jsonify([dict(o) for o in orders])

@app.route('/api/stockist/my-stock', methods=['GET'])
@role_required(['super_stockist'])
def stockist_my_stock():
    """Super Stockist views stock at their own location."""
    stock_data = query_db("""
        SELECT i.id, p.name as product_name, b.batch_no, i.quantity, b.exp_date, i.last_updated
        FROM inventory i
        JOIN products p ON i.product_id = p.id
        JOIN batches b ON i.batch_id = b.id
        WHERE i.location_user_id = ? AND i.location_type = 'super_stockist'
    """, (g.user_id,))
    return jsonify([dict(s) for s in stock_data])

@app.route('/api/stockist/audit-trail', methods=['GET'])
@role_required(['super_stockist'])
def stockist_audit_trail():
    """Retrieves audit logs for the current Super Stockist user."""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    action_filter = request.args.get('action')

    query = """
        SELECT a.timestamp, u.username as user, u.role, a.action, a.entity_type, a.entity_id, a.details, a.ip_address
        FROM audit_trail a
        JOIN users u ON a.user_id = u.id
        WHERE u.id = ?
    """
    params = [g.user_id]

    if start_date:
        query += " AND a.timestamp >= ?"
        params.append(start_date)
    if end_date:
        query += " AND a.timestamp <= ?"
        params.append(end_date)
    if action_filter:
        query += " AND a.action LIKE ?"
        params.append(f"%{action_filter}%")
    
    query += " ORDER BY a.timestamp DESC"

    logs = query_db(query, tuple(params))
    for log in logs:
        if log['details']:
            log['details'] = json.loads(log['details'])
    return jsonify([dict(l) for l in logs])

@app.route('/api/stockist/sales-data', methods=['GET'])
@role_required(['super_stockist'])
def stockist_sales_data():
    """Provides dummy sales data for stockist chart."""
    # In a real app, this would query sales transactions from a 'sales' table,
    # or be calculated based on dispatches to retailers if that's part of the scope.
    # For now, it returns fixed dummy data as in your HTML.
    return jsonify([
        {"month": "Jan", "sales": 5000},
        {"month": "Feb", "sales": 7500},
        {"month": "Mar", "sales": 6000},
        {"month": "Apr", "sales": 8000},
        {"month": "May", "sales": 9500},
        {"month": "Jun", "sales": 11000}
    ])


# --- Serve HTML Files ---

@app.route('/')
def serve_index():
    """Serves the main login/index page (you might need to create an index.html)."""
    # Assuming you have an index.html for the login screen
    return send_from_directory(app.static_folder, 'index.html' if os.path.exists(os.path.join(app.static_folder, 'index.html')) else 'login.html')

@app.route('/manufacturer.html')
def serve_manufacturer():
    """Serves the manufacturer dashboard."""
    return send_from_directory(app.static_folder, 'manufacterer.html')

@app.route('/cfa.html')
def serve_cfa():
    """Serves the CFA dashboard."""
    return send_from_directory(app.static_folder, 'cfa.html')

@app.route('/stockist.html')
def serve_stockist():
    """Serves the Super Stockist dashboard."""
    return send_from_directory(app.static_folder, 'stockist.html')

# If you have other static assets like CSS, JS, they are served automatically from 'static'


# --- Main Execution ---

if __name__ == '__main__':
    # Initialize the database if it doesn't exist
    if not os.path.exists(DATABASE):
        init_db()
        # Add a default manufacturer admin user for initial testing
        with app.app_context():
            db = get_db()
            # Check if manufacturer user already exists to avoid duplicates on restart
            existing_manufacturer = query_db("SELECT id FROM users WHERE role = 'manufacturer'", one=True)
            if not existing_manufacturer:
                db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                           ('manufacturer_admin', generate_password_hash('adminpass'), 'manufacturer'))
                db.commit()
                print("Default manufacturer_admin user created (username: manufacturer_admin, password: adminpass)")
            
            # Add a default CFA user
            existing_cfa = query_db("SELECT id FROM users WHERE role = 'cfa'", one=True)
            if not existing_cfa:
                db.execute("INSERT INTO users (username, password, role, location) VALUES (?, ?, ?, ?)",
                           ('cfa_user', generate_password_hash('cfapass'), 'cfa', 'Mumbai'))
                db.commit()
                print("Default cfa_user created (username: cfa_user, password: cfapass)")

            # Add a default Super Stockist user, linked to the CFA user
            existing_stockist = query_db("SELECT id FROM users WHERE role = 'super_stockist'", one=True)
            if not existing_stockist:
                cfa_id = query_db("SELECT id FROM users WHERE username = 'cfa_user'", one=True)['id']
                db.execute("INSERT INTO users (username, password, role, location, cfa_id) VALUES (?, ?, ?, ?, ?)",
                           ('stockist_user', generate_password_hash('stockistpass'), 'super_stockist', 'Pune', cfa_id))
                db.commit()
                print("Default stockist_user created (username: stockist_user, password: stockistpass)")


    app.run(debug=True) # Run Flask app in debug mode
