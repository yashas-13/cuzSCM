# **Supply Chain Management System: Detailed Development Instructions**

This section provides a comprehensive, instruction-based guide to developing the Supply Chain Management (SCM) system. It covers project setup, backend API development, database design, and frontend implementation, emphasizing best practices for building a robust and scalable application.

## **1\. Project Setup and Structure**

A well-organized project structure is crucial for maintainability and scalability.

1. **Initialize Project Directory:**  
   mkdir supply\_chain\_system  
   cd supply\_chain\_system

2. Create Virtual Environment:  
   Isolate project dependencies to avoid conflicts.  
   python \-m venv venv  
   \# Activate:  
   \# Windows: .\\venv\\Scripts\\activate  
   \# macOS/Linux: source venv/bin/activate

3. Basic Project Structure:  
   Create directories for different components.  
   supply\_chain\_system/  
   ├── venv/                      \# Python virtual environment  
   ├── app/                       \# Main application source code  
   │   ├── \_\_init\_\_.py            \# Application factory, blueprint registration  
   │   ├── api/                   \# REST API endpoints  
   │   │   ├── \_\_init\_\_.py  
   │   │   ├── auth.py            \# Authentication routes  
   │   │   ├── products.py        \# Product API routes  
   │   │   ├── inventory.py       \# Inventory API routes  
   │   │   └── orders.py          \# Order API routes  
   │   ├── models/                \# SQLAlchemy database models  
   │   │   ├── \_\_init\_\_.py  
   │   │   └── user.py  
   │   │   └── product.py  
   │   │   └── inventory.py  
   │   │   └── order.py  
   │   ├── services/              \# Business logic, service layer  
   │   │   ├── \_\_init\_\_.py  
   │   │   ├── product\_service.py  
   │   │   └── order\_service.py  
   │   ├── static/                \# Frontend static files (CSS, JS, images)  
   │   │   ├── css/  
   │   │   │   └── style.css      \# Custom CSS  
   │   │   ├── js/  
   │   │   │   └── main.js        \# Main JavaScript logic  
   │   │   │   └── charts.js      \# Chart.js specific code  
   │   │   └── img/  
   │   ├── templates/             \# Jinja2 HTML templates  
   │   │   ├── base.html          \# Base layout  
   │   │   ├── index.html   
4.  |     |    |── \*.html(manufacterer.html,cfa.html,super\_stockist.html)         \# Dashboard  
   │   │   ├── auth/  
   │   │   │   ├── login.html  
   │   │   │   └── register.html  
   │   │   ├── products/  
   │   │   │   └── list.html  
   │   │   └── orders/  
   │   │       └── list.html  
   │   ├── config.py              \# Application configurations  
   │   └── extensions.py          \# Flask extensions (SQLAlchemy, Bcrypt etc.)  
   ├── tests/                     \# Unit and integration tests  
   │   ├── \_\_init\_\_.py  
   │   └── test\_api.py  
   ├── instance/                  \# Instance-specific configurations (e.g., development.cfg)  
   ├── .gitignore                 \# Git ignore file  
   ├── requirements.txt           \# Python dependencies  
   └── run.py                     \# Entry point to run the application

5. Create requirements.txt:  
   List all Python packages your project depends on.  
   \# Example content for requirements.txt  
   Flask  
   SQLAlchemy  
   Flask-SQLAlchemy  
   Flask-Migrate          \# For database migrations  
   Flask-Bcrypt           \# For password hashing  
   Flask-JWT-Extended     \# For token-based authentication (if using JWT)  
   python-dotenv          \# For environment variables  
   gunicorn               \# Production WSGI server  
   psycopg2-binary        \# If you decide to use PostgreSQL in production

   Install them: pip install \-r requirements.txt

## **2\. Database Design with SQLite and SQLAlchemy**

SQLAlchemy provides an Object Relational Mapper (ORM) that maps Python classes to database tables.

1. **Configure SQLAlchemy (app/extensions.py and app/config.py):**  
   \# app/extensions.py  
   from flask\_sqlalchemy import SQLAlchemy  
   from flask\_migrate import Migrate  
   from flask\_bcrypt import Bcrypt  
   from flask\_jwt\_extended import JWTManager

   db \= SQLAlchemy()  
   migrate \= Migrate()  
   bcrypt \= Bcrypt()  
   jwt \= JWTManager()

   \# app/config.py  
   import os

   basedir \= os.path.abspath(os.path.dirname(\_\_file\_\_))

   class Config:  
       SECRET\_KEY \= os.environ.get('SECRET\_KEY') or 'a\_very\_secret\_key\_that\_should\_be\_changed'  
       SQLALCHEMY\_DATABASE\_URI \= os.environ.get('DATABASE\_URL') or \\  
                                 'sqlite:///' \+ os.path.join(basedir, '../instance/app.db')  
       SQLALCHEMY\_TRACK\_MODIFICATIONS \= False  
       JWT\_SECRET\_KEY \= os.environ.get('JWT\_SECRET\_KEY') or 'jwt\_super\_secret\_key'

   \# .env (create this file in the root directory for development)  
   \# SECRET\_KEY=your\_flask\_secret\_key  
   \# DATABASE\_URL=sqlite:///instance/app.db  
   \# JWT\_SECRET\_KEY=your\_jwt\_secret\_key

2. Define Models (app/models/):  
   Each model represents a table in your database.  
   * app/models/user.py:  
     from app.extensions import db, bcrypt  
     from datetime import datetime

     class User(db.Model):  
         id \= db.Column(db.Integer, primary\_key=True)  
         username \= db.Column(db.String(80), unique=True, nullable=False)  
         email \= db.Column(db.String(120), unique=True, nullable=False)  
         password\_hash \= db.Column(db.String(128), nullable=False)  
         role \= db.Column(db.String(20), nullable=False, default='super\_stockist') \# manufacturer, cfa, super\_stockist  
         created\_at \= db.Column(db.DateTime, default=datetime.utcnow)

         \# Relationships  
         \# For Manufacturer/CFA: can manage multiple products, inventory locations  
         \# For CFA: can manage multiple inventory locations, orders  
         \# For Super Stockist: can create multiple orders

         def set\_password(self, password):  
             self.password\_hash \= bcrypt.generate\_password\_hash(password).decode('utf-8')

         def check\_password(self, password):  
             return bcrypt.check\_password\_hash(self.password\_hash, password)

         def \_\_repr\_\_(self):  
             return f'\<User {self.username}\>'

   * app/models/product.py:  
     from app.extensions import db  
     from datetime import datetime

     class Product(db.Model):  
         id \= db.Column(db.Integer, primary\_key=True)  
         name \= db.Column(db.String(100), nullable=False)  
         sku \= db.Column(db.String(50), unique=True, nullable=False)  
         description \= db.Column(db.Text)  
         dosage \= db.Column(db.String(50))  
         price \= db.Column(db.Float, nullable=False)  
         manufacturer\_id \= db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
         manufacturer \= db.relationship('User', backref=db.backref('products', lazy=True))  
         created\_at \= db.Column(db.DateTime, default=datetime.utcnow)  
         updated\_at \= db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

         def \_\_repr\_\_(self):  
             return f'\<Product {self.name}\>'

   * app/models/inventory.py:  
     from app.extensions import db  
     from datetime import datetime

     class Inventory(db.Model):  
         id \= db.Column(db.Integer, primary\_key=True)  
         product\_id \= db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)  
         product \= db.relationship('Product', backref=db.backref('inventory\_records', lazy=True))  
         location\_type \= db.Column(db.String(50), nullable=False) \# 'manufacturer', 'cfa', 'super\_stockist'  
         location\_id \= db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) \# User ID of the entity holding stock  
         location\_entity \= db.relationship('User', backref=db.backref('inventory\_at\_location', lazy=True))  
         quantity \= db.Column(db.Integer, nullable=False, default=0)  
         last\_updated \= db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

         def \_\_repr\_\_(self):  
             return f'\<Inventory {self.product.name} at {self.location\_type}-{self.location\_id}: {self.quantity}\>'

   * app/models/order.py:  
     from app.extensions import db  
     from datetime import datetime

     class Order(db.Model):  
         id \= db.Column(db.Integer, primary\_key=True)  
         order\_from\_id \= db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) \# E.g., Super Stockist  
         order\_to\_id \= db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)   \# E.g., CFA or Manufacturer  
         status \= db.Column(db.String(20), nullable=False, default='pending') \# pending, processing, shipped, delivered, cancelled  
         total\_amount \= db.Column(db.Float, nullable=False, default=0.0)  
         created\_at \= db.Column(db.DateTime, default=datetime.utcnow)  
         updated\_at \= db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

         order\_from\_user \= db.relationship('User', foreign\_keys=\[order\_from\_id\], backref=db.backref('placed\_orders', lazy=True))  
         order\_to\_user \= db.relationship('User', foreign\_keys=\[order\_to\_id\], backref=db.backref('received\_orders', lazy=True))

         items \= db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

         def \_\_repr\_\_(self):  
             return f'\<Order {self.id} from {self.order\_from\_id} to {self.order\_to\_id} \- Status: {self.status}\>'

     class OrderItem(db.Model):  
         id \= db.Column(db.Integer, primary\_key=True)  
         order\_id \= db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)  
         product\_id \= db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)  
         product \= db.relationship('Product', backref=db.backref('order\_items', lazy=True))  
         quantity \= db.Column(db.Integer, nullable=False)  
         price\_at\_order \= db.Column(db.Float, nullable=False) \# Price at the time of order

         def \_\_repr\_\_(self):  
             return f'\<OrderItem {self.id} for Order {self.order\_id}: {self.quantity} x {self.product.name}\>'

3. Database Migrations (using Flask-Migrate):  
   Flask-Migrate helps manage database schema changes.  
   * **Initialize Migrations:**  
     flask db init

   * **Create Migration:**  
     flask db migrate \-m "Initial migration"

   * **Apply Migration:**  
     flask db upgrade

   * For subsequent model changes, run flask db migrate then flask db upgrade.

## **3\. REST API Development with Python (Flask)**

Build a RESTful API to expose data and functionalities to the frontend.

1. **Application Factory (app/\_\_init\_\_.py):**  
   import os  
   from flask import Flask  
   from app.config import Config  
   from app.extensions import db, migrate, bcrypt, jwt  
   from app.api.auth import auth\_bp  
   from app.api.products import products\_bp  
   from app.api.inventory import inventory\_bp  
   from app.api.orders import orders\_bp  
   from dotenv import load\_dotenv

   load\_dotenv() \# Load environment variables from .env file

   def create\_app(config\_class=Config):  
       app \= Flask(\_\_name\_\_)  
       app.config.from\_object(config\_class)

       \# Initialize extensions  
       db.init\_app(app)  
       migrate.init\_app(app, db)  
       bcrypt.init\_app(app)  
       jwt.init\_app(app)

       \# Register blueprints  
       app.register\_blueprint(auth\_bp, url\_prefix='/api/auth')  
       app.register\_blueprint(products\_bp, url\_prefix='/api/products')  
       app.register\_blueprint(inventory\_bp, url\_prefix='/api/inventory')  
       app.register\_blueprint(orders\_bp, url\_prefix='/api/orders')

       \# Import models so they are registered with SQLAlchemy  
       from app.models import user, product, inventory, order

       \# Basic route for testing  
       @app.route('/')  
       def index():  
           return "Welcome to the Supply Chain Management System\!"

       return app

   \# run.py (main entry point)  
   from app import create\_app

   app \= create\_app()

   if \_\_name\_\_ \== '\_\_main\_\_':  
       app.run(debug=True)

2. Authentication (app/api/auth.py):  
   Implement user registration and login, returning JWT tokens for authentication.  
   from flask import Blueprint, request, jsonify  
   from app.models.user import User  
   from app.extensions import db, bcrypt, jwt  
   from flask\_jwt\_extended import create\_access\_token, jwt\_required, get\_jwt\_identity

   auth\_bp \= Blueprint('auth', \_\_name\_\_)

   @auth\_bp.route('/register', methods=\['POST'\])  
   def register():  
       data \= request.get\_json()  
       username \= data.get('username')  
       email \= data.get('email')  
       password \= data.get('password')  
       role \= data.get('role', 'super\_stockist') \# Default role

       if not username or not email or not password:  
           return jsonify({'message': 'Missing username, email, or password'}), 400

       if User.query.filter\_by(username=username).first() or User.query.filter\_by(email=email).first():  
           return jsonify({'message': 'User with this username or email already exists'}), 409

       new\_user \= User(username=username, email=email, role=role)  
       new\_user.set\_password(password)  
       db.session.add(new\_user)  
       db.session.commit()

       return jsonify({'message': 'User registered successfully', 'user\_id': new\_user.id}), 201

   @auth\_bp.route('/login', methods=\['POST'\])  
   def login():  
       data \= request.get\_json()  
       username \= data.get('username')  
       password \= data.get('password')

       user \= User.query.filter\_by(username=username).first()

       if not user or not user.check\_password(password):  
           return jsonify({'message': 'Invalid credentials'}), 401

       access\_token \= create\_access\_token(identity={'id': user.id, 'role': user.role})  
       return jsonify(access\_token=access\_token, user\_role=user.role), 200

   @auth\_bp.route('/protected', methods=\['GET'\])  
   @jwt\_required()  
   def protected():  
       current\_user\_identity \= get\_jwt\_identity()  
       return jsonify(logged\_in\_as=current\_user\_identity), 200

3. **Products API (app/api/products.py):**  
   from flask import Blueprint, request, jsonify  
   from app.models.product import Product  
   from app.models.user import User  
   from app.extensions import db  
   from flask\_jwt\_extended import jwt\_required, get\_jwt\_identity  
   from functools import wraps

   products\_bp \= Blueprint('products', \_\_name\_\_)

   def role\_required(allowed\_roles):  
       def decorator(fn):  
           @wraps(fn)  
           @jwt\_required()  
           def wrapper(\*args, \*\*kwargs):  
               current\_user\_identity \= get\_jwt\_identity()  
               user\_role \= current\_user\_identity.get('role')  
               if user\_role not in allowed\_roles:  
                   return jsonify({'message': 'Access forbidden: Insufficient permissions'}), 403  
               return fn(\*args, \*\*kwargs)  
           return wrapper  
       return decorator

   @products\_bp.route('/', methods=\['POST'\])  
   @role\_required(\['manufacturer'\])  
   def add\_product():  
       data \= request.get\_json()  
       current\_user\_identity \= get\_jwt\_identity()  
       manufacturer\_id \= current\_user\_identity.get('id')

       \# Basic validation  
       if not all(key in data for key in \['name', 'sku', 'price'\]):  
           return jsonify({'message': 'Missing product data'}), 400

       \# Check if SKU already exists  
       if Product.query.filter\_by(sku=data\['sku'\]).first():  
           return jsonify({'message': 'Product with this SKU already exists'}), 409

       new\_product \= Product(  
           name=data\['name'\],  
           sku=data\['sku'\],  
           description=data.get('description'),  
           dosage=data.get('dosage'),  
           price=data\['price'\],  
           manufacturer\_id=manufacturer\_id  
       )  
       db.session.add(new\_product)  
       db.session.commit()  
       return jsonify({'message': 'Product added successfully', 'product\_id': new\_product.id}), 201

   @products\_bp.route('/', methods=\['GET'\])  
   @jwt\_required() \# All authenticated users can view products  
   def get\_products():  
       products \= Product.query.all()  
       return jsonify(\[{  
           'id': p.id,  
           'name': p.name,  
           'sku': p.sku,  
           'description': p.description,  
           'dosage': p.dosage,  
           'price': p.price,  
           'manufacturer': p.manufacturer.username if p.manufacturer else 'N/A'  
       } for p in products\]), 200

   \# Add routes for PUT (update) and DELETE product as needed

4. **Inventory API (app/api/inventory.py):**  
   from flask import Blueprint, request, jsonify  
   from app.models.inventory import Inventory  
   from app.models.product import Product  
   from app.models.user import User  
   from app.extensions import db  
   from flask\_jwt\_extended import jwt\_required, get\_jwt\_identity  
   from app.api.products import role\_required \# Re-use role\_required decorator

   inventory\_bp \= Blueprint('inventory', \_\_name\_\_)

   @inventory\_bp.route('/', methods=\['POST'\])  
   @role\_required(\['manufacturer', 'cfa', 'super\_stockist'\]) \# Allows adding stock to own location  
   def add\_stock():  
       data \= request.get\_json()  
       current\_user\_identity \= get\_jwt\_identity()  
       user\_id \= current\_user\_identity.get('id')  
       user\_role \= current\_user\_identity.get('role')

       product\_id \= data.get('product\_id')  
       quantity \= data.get('quantity')

       if not all(\[product\_id, quantity\]):  
           return jsonify({'message': 'Missing product\_id or quantity'}), 400  
       if not isinstance(quantity, int) or quantity \<= 0:  
           return jsonify({'message': 'Quantity must be a positive integer'}), 400

       product \= Product.query.get(product\_id)  
       if not product:  
           return jsonify({'message': 'Product not found'}), 404

       inventory\_record \= Inventory.query.filter\_by(  
           product\_id=product\_id,  
           location\_id=user\_id,  
           location\_type=user\_role  
       ).first()

       if inventory\_record:  
           inventory\_record.quantity \+= quantity  
       else:  
           inventory\_record \= Inventory(  
               product\_id=product\_id,  
               location\_type=user\_role,  
               location\_id=user\_id,  
               quantity=quantity  
           )  
           db.session.add(inventory\_record)

       db.session.commit()  
       return jsonify({'message': 'Stock updated successfully', 'current\_quantity': inventory\_record.quantity}), 200

   @inventory\_bp.route('/\<int:location\_id\>', methods=\['GET'\])  
   @jwt\_required()  
   def get\_inventory\_by\_location(location\_id):  
       \# A user can only view their own inventory or if they have permission (e.g., Manufacturer can view CFA/SS inventory)  
       current\_user\_identity \= get\_jwt\_identity()  
       requester\_id \= current\_user\_identity.get('id')  
       requester\_role \= current\_user\_identity.get('role')

       \# Allow user to view their own inventory  
       if requester\_id \!= location\_id:  
           \# Implement more complex logic for cross-role visibility here  
           \# E.g., Manufacturer can see CFA/SS inventory. CFA can see SS inventory.  
           target\_user \= User.query.get(location\_id)  
           if not target\_user:  
               return jsonify({'message': 'Location user not found'}), 404

           \# Example: Manufacturer can view CFA/SS inventory  
           if requester\_role \== 'manufacturer' and target\_user.role in \['cfa', 'super\_stockist'\]:  
               pass \# Allowed  
           \# Example: CFA can view Super Stockist inventory  
           elif requester\_role \== 'cfa' and target\_user.role \== 'super\_stockist':  
               pass \# Allowed  
           else:  
               return jsonify({'message': 'Access forbidden: Not authorized to view this inventory'}), 403

       inventory\_records \= Inventory.query.filter\_by(location\_id=location\_id).all()  
       return jsonify(\[{  
           'product\_id': inv.product.id,  
           'product\_name': inv.product.name,  
           'sku': inv.product.sku,  
           'quantity': inv.quantity,  
           'location\_type': inv.location\_type,  
           'location\_id': inv.location\_id,  
           'last\_updated': inv.last\_updated.isoformat()  
       } for inv in inventory\_records\]), 200

5. **Orders API (app/api/orders.py):**  
   from flask import Blueprint, request, jsonify  
   from app.models.order import Order, OrderItem  
   from app.models.product import Product  
   from app.models.inventory import Inventory  
   from app.models.user import User  
   from app.extensions import db  
   from flask\_jwt\_extended import jwt\_required, get\_jwt\_identity  
   from app.api.products import role\_required \# Re-use role\_required decorator

   orders\_bp \= Blueprint('orders', \_\_name\_\_)

   @orders\_bp.route('/', methods=\['POST'\])  
   @role\_required(\['super\_stockist', 'cfa'\]) \# Super Stockist orders CFA, CFA orders Manufacturer  
   def create\_order():  
       data \= request.get\_json()  
       current\_user\_identity \= get\_jwt\_identity()  
       order\_from\_id \= current\_user\_identity.get('id')  
       order\_from\_role \= current\_user\_identity.get('role')

       order\_to\_id \= data.get('order\_to\_id')  
       items \= data.get('items') \# \[{'product\_id': 1, 'quantity': 10}\]

       if not all(\[order\_to\_id, items\]) or not isinstance(items, list):  
           return jsonify({'message': 'Missing order\_to\_id or items list'}), 400

       order\_to\_user \= User.query.get(order\_to\_id)  
       if not order\_to\_user:  
           return jsonify({'message': 'Recipient user not found'}), 404

       \# Logic for who can order from whom  
       if order\_from\_role \== 'super\_stockist' and order\_to\_user.role \!= 'cfa':  
           return jsonify({'message': 'Super Stockist can only order from CFA'}), 403  
       elif order\_from\_role \== 'cfa' and order\_to\_user.role \!= 'manufacturer':  
           return jsonify({'message': 'CFA can only order from Manufacturer'}), 403  
       elif order\_from\_role \== 'manufacturer': \# Manufacturer cannot place orders through the system this way  
            return jsonify({'message': 'Manufacturer cannot place orders from this interface'}), 403

       new\_order \= Order(  
           order\_from\_id=order\_from\_id,  
           order\_to\_id=order\_to\_id,  
           status='pending',  
           total\_amount=0.0  
       )  
       db.session.add(new\_order)  
       db.session.flush() \# To get the order\_id before committing

       calculated\_total \= 0.0  
       for item\_data in items:  
           product \= Product.query.get(item\_data\['product\_id'\])  
           if not product:  
               db.session.rollback()  
               return jsonify({'message': f'Product with ID {item\_data\["product\_id"\]} not found'}), 404

           \# Check available stock at the source (order\_to\_id's inventory)  
           source\_inventory \= Inventory.query.filter\_by(  
               product\_id=product.id,  
               location\_id=order\_to\_id,  
               location\_type=order\_to\_user.role  
           ).first()

           if not source\_inventory or source\_inventory.quantity \< item\_data\['quantity'\]:  
               db.session.rollback()  
               return jsonify({'message': f'Insufficient stock for {product.name} at {order\_to\_user.username}\\'s location. Available: {source\_inventory.quantity if source\_inventory else 0}'}), 400

           order\_item \= OrderItem(  
               order\_id=new\_order.id,  
               product\_id=product.id,  
               quantity=item\_data\['quantity'\],  
               price\_at\_order=product.price  
           )  
           db.session.add(order\_item)  
           calculated\_total \+= (product.price \* item\_data\['quantity'\])

       new\_order.total\_amount \= calculated\_total  
       db.session.commit()

       return jsonify({'message': 'Order placed successfully', 'order\_id': new\_order.id, 'total\_amount': new\_order.total\_amount}), 201

   @orders\_bp.route('/\<int:order\_id\>/status', methods=\['PUT'\])  
   @role\_required(\['manufacturer', 'cfa'\]) \# Only Manufacturer/CFA can update order status  
   def update\_order\_status(order\_id):  
       data \= request.get\_json()  
       new\_status \= data.get('status')  
       current\_user\_identity \= get\_jwt\_identity()  
       user\_id \= current\_user\_identity.get('id')  
       user\_role \= current\_user\_identity.get('role')

       order \= Order.query.get(order\_id)  
       if not order:  
           return jsonify({'message': 'Order not found'}), 404

       \# Ensure only the intended recipient of the order can update its status  
       if order.order\_to\_id \!= user\_id or order.order\_to\_user.role \!= user\_role:  
           return jsonify({'message': 'Access forbidden: You are not authorized to update this order'}), 403

       \# Validate new status  
       allowed\_statuses \= \['pending', 'processing', 'shipped', 'delivered', 'cancelled'\]  
       if new\_status not in allowed\_statuses:  
           return jsonify({'message': 'Invalid status provided'}), 400

       \# Implement stock deduction logic on 'shipped' status  
       if new\_status \== 'shipped' and order.status \!= 'shipped':  
           for item in order.items:  
               inventory \= Inventory.query.filter\_by(  
                   product\_id=item.product\_id,  
                   location\_id=order.order\_to\_id,  
                   location\_type=order.order\_to\_user.role  
               ).first()  
               if inventory and inventory.quantity \>= item.quantity:  
                   inventory.quantity \-= item.quantity  
               else:  
                   \# Rollback if stock becomes insufficient at the last minute  
                   db.session.rollback()  
                   return jsonify({'message': f'Failed to update order status. Insufficient stock for {item.product.name}'}), 400

       order.status \= new\_status  
       db.session.commit()  
       return jsonify({'message': f'Order {order\_id} status updated to {new\_status}'}), 200

   @orders\_bp.route('/', methods=\['GET'\])  
   @jwt\_required()  
   def get\_orders():  
       current\_user\_identity \= get\_jwt\_identity()  
       user\_id \= current\_user\_identity.get('id')  
       user\_role \= current\_user\_identity.get('role')

       \# Fetch orders placed by the user or received by the user  
       if user\_role \== 'manufacturer':  
           orders \= Order.query.filter\_by(order\_to\_id=user\_id).all() \# Manufacturer receives orders from CFA  
       elif user\_role \== 'cfa':  
           orders \= Order.query.filter(  
               (Order.order\_from\_id \== user\_id) | \# Orders placed by CFA  
               (Order.order\_to\_id \== user\_id)     \# Orders received by CFA from SS  
           ).all()  
       elif user\_role \== 'super\_stockist':  
           orders \= Order.query.filter\_by(order\_from\_id=user\_id).all() \# Orders placed by Super Stockist  
       else:  
           orders \= \[\]

       result \= \[\]  
       for order in orders:  
           items\_data \= \[{  
               'product\_id': item.product.id,  
               'product\_name': item.product.name,  
               'quantity': item.quantity,  
               'price\_at\_order': item.price\_at\_order  
           } for item in order.items\]  
           result.append({  
               'id': order.id,  
               'order\_from': order.order\_from\_user.username,  
               'order\_to': order.order\_to\_user.username,  
               'status': order.status,  
               'total\_amount': order.total\_amount,  
               'created\_at': order.created\_at.isoformat(),  
               'updated\_at': order.updated\_at.isoformat(),  
               'items': items\_data  
           })  
       return jsonify(result), 200

## **4\. Frontend Development (Bootstrap, HTML, CSS, JS, Chart.js)**

Create a responsive and interactive user interface.

1. Integrate Bootstrap 5:  
   Include Bootstrap CSS and JS in your app/templates/base.html.  
   \<\!-- app/templates/base.html \--\>  
   \<\!DOCTYPE html\>  
   \<html lang="en"\>  
   \<head\>  
       \<meta charset="UTF-8"\>  
       \<meta name="viewport" content="width=device-width, initial-scale=1.0"\>  
       \<title\>{% block title %}SCM System{% endblock %}\</title\>  
       \<\!-- Bootstrap CSS \--\>  
       \<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous"\>  
       \<\!-- Custom CSS \--\>  
       \<link rel="stylesheet" href="{{ url\_for('static', filename='css/style.css') }}"\>  
       \<\!-- Google Fonts \- Inter \--\>  
       \<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700\&display=swap" rel="stylesheet"\>  
       \<style\>  
           body { font-family: 'Inter', sans-serif; }  
           /\* Global rounded corners for most elements \*/  
           .card, .btn, .form-control, .table, .modal-content {  
               border-radius: 0.75rem \!important;  
           }  
           .navbar { border-radius: 0 0 0.75rem 0.75rem \!important; } /\* Only bottom corners \*/  
       \</style\>  
       {% block head\_extra %}{% endblock %}  
   \</head\>  
   \<body\>  
       \<nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm mb-4"\>  
           \<div class="container-fluid"\>  
               \<a class="navbar-brand" href="\#"\>SCM Dashboard\</a\>  
               \<button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="\#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation"\>  
                   \<span class="navbar-toggler-icon"\>\</span\>  
               \</button\>  
               \<div class="collapse navbar-collapse" id="navbarNav"\>  
                   \<ul class="navbar-nav me-auto mb-2 mb-lg-0"\>  
                       \<li class="nav-item"\>  
                           \<a class="nav-link" href="\#" id="nav-dashboard"\>Dashboard\</a\>  
                       \</li\>  
                       \<li class="nav-item"\>  
                           \<a class="nav-link" href="\#" id="nav-products"\>Products\</a\>  
                       \</li\>  
                       \<li class="nav-item"\>  
                           \<a class="nav-link" href="\#" id="nav-inventory"\>Inventory\</a\>  
                       \</li\>  
                       \<li class="nav-item"\>  
                           \<a class="nav-link" href="\#" id="nav-orders"\>Orders\</a\>  
                       \</li\>  
                   \</ul\>  
                   \<div class="d-flex"\>  
                       \<span class="navbar-text me-3" id="current-user-info"\>  
                           Not logged in  
                       \</span\>  
                       \<button class="btn btn-outline-light" id="logout-btn"\>Logout\</button\>  
                   \</div\>  
               \</div\>  
           \</div\>  
       \</nav\>

       \<div class="container-fluid"\>  
           {% block content %}{% endblock %}  
       \</div\>

       \<\!-- Bootstrap JS \--\>  
       \<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"\>\</script\>  
       \<\!-- Chart.js \--\>  
       \<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"\>\</script\>  
       \<\!-- Custom JS \--\>  
       \<script src="{{ url\_for('static', filename='js/main.js') }}"\>\</script\>  
       \<script src="{{ url\_for('static', filename='js/charts.js') }}"\>\</script\>  
       {% block scripts\_extra %}{% endblock %}  
   \</body\>  
   \</html\>

2. Dashboard (app/templates/index.html):  
   This will be the main landing page after login. It dynamically loads content using JavaScript.  
   \<\!-- app/templates/index.html \--\>  
   {% extends "base.html" %}

   {% block title %}Dashboard{% endblock %}

   {% block content %}  
   \<div id="content-area"\>  
       \<\!-- Content will be loaded here by JavaScript \--\>  
       \<div class="d-flex justify-content-center align-items-center" style="min-height: 60vh;"\>  
           \<div class="spinner-border text-primary" role="status"\>  
               \<span class="visually-hidden"\>Loading...\</span\>  
           \</div\>  
           \<p class="ms-3 text-muted"\>Loading dashboard...\</p\>  
       \</div\>  
   \</div\>

   \<\!-- Modals for forms, messages etc. \--\>  
   \<div class="modal fade" id="messageModal" tabindex="-1" aria-labelledby="messageModalLabel" aria-hidden="true"\>  
       \<div class="modal-dialog modal-dialog-centered"\>  
           \<div class="modal-content"\>  
               \<div class="modal-header bg-success text-white"\>  
                   \<h5 class="modal-title" id="messageModalLabel"\>Notification\</h5\>  
                   \<button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"\>\</button\>  
               \</div\>  
               \<div class="modal-body" id="messageModalBody"\>  
                   \<\!-- Message content \--\>  
               \</div\>  
               \<div class="modal-footer"\>  
                   \<button type="button" class="btn btn-secondary" data-bs-dismiss="modal"\>Close\</button\>  
               \</div\>  
           \</div\>  
       \</div\>  
   \</div\>  
   {% endblock %}

   {% block scripts\_extra %}  
   \<script\>  
       document.addEventListener('DOMContentLoaded', function() {  
           // Initial content load for the dashboard  
           loadContent('dashboard'); // Assuming 'dashboard' is a function in main.js  
       });  
   \</script\>  
   {% endblock %}

3. Login/Register Pages (app/templates/auth/login.html, register.html):  
   These will be rendered directly by Flask before any JWT is issued.  
   \<\!-- app/templates/auth/login.html \--\>  
   {% extends "base.html" %}

   {% block title %}Login{% endblock %}

   {% block content %}  
   \<div class="row justify-content-center mt-5"\>  
       \<div class="col-md-5 col-lg-4"\>  
           \<div class="card shadow-lg p-4"\>  
               \<h2 class="card-title text-center mb-4"\>Login\</h2\>  
               \<form id="login-form"\>  
                   \<div class="mb-3"\>  
                       \<label for="username" class="form-label"\>Username\</label\>  
                       \<input type="text" class="form-control" id="username" required\>  
                   \</div\>  
                   \<div class="mb-3"\>  
                       \<label for="password" class="form-label"\>Password\</label\>  
                       \<input type="password" class="form-control" id="password" required\>  
                   \</div\>  
                   \<button type="submit" class="btn btn-primary w-100 py-2"\>Login\</button\>  
                   \<p class="text-center mt-3"\>  
                       Don't have an account? \<a href="/register"\>Register here\</a\>  
                   \</p\>  
               \</form\>  
               \<div id="login-message" class="mt-3 text-center text-danger"\>\</div\>  
           \</div\>  
       \</div\>  
   \</div\>  
   {% endblock %}

   {% block scripts\_extra %}  
   \<script\>  
       document.getElementById('login-form').addEventListener('submit', async function(event) {  
           event.preventDefault();  
           const username \= document.getElementById('username').value;  
           const password \= document.getElementById('password').value;  
           const messageDiv \= document.getElementById('login-message');

           try {  
               const response \= await fetch('/api/auth/login', {  
                   method: 'POST',  
                   headers: { 'Content-Type': 'application/json' },  
                   body: JSON.stringify({ username, password })  
               });  
               const data \= await response.json();

               if (response.ok) {  
                   localStorage.setItem('access\_token', data.access\_token);  
                   localStorage.setItem('user\_role', data.user\_role);  
                   window.location.href \= '/'; // Redirect to dashboard  
               } else {  
                   messageDiv.textContent \= data.message || 'Login failed';  
               }  
           } catch (error) {  
               console.error('Error:', error);  
               messageDiv.textContent \= 'An error occurred. Please try again.';  
           }  
       });  
   \</script\>  
   {% endblock %}

   (Similar structure for register.html, hitting /api/auth/register)  
4. Main JavaScript (app/static/js/main.js):  
   Handles API calls, dynamic content loading, and general UI logic.  
   // app/static/js/main.js

   const API\_BASE\_URL \= '/api';  
   const contentArea \= document.getElementById('content-area');  
   const currentUserInfo \= document.getElementById('current-user-info');  
   const messageModal \= new bootstrap.Modal(document.getElementById('messageModal'));  
   const messageModalBody \= document.getElementById('messageModalBody');

   // Utility function to show messages  
   function showMessage(message, isSuccess \= true) {  
       messageModalBody.textContent \= message;  
       const modalHeader \= document.querySelector('\#messageModal .modal-header');  
       if (isSuccess) {  
           modalHeader.classList.remove('bg-danger');  
           modalHeader.classList.add('bg-success');  
       } else {  
           modalHeader.classList.remove('bg-success');  
           modalHeader.classList.add('bg-danger');  
       }  
       messageModal.show();  
   }

   // Function to get JWT token  
   function getAuthHeaders() {  
       const token \= localStorage.getItem('access\_token');  
       return token ? { 'Authorization': \`Bearer ${token}\`, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' };  
   }

   // Function to update user info in navbar  
   function updateUserInfo() {  
       const userRole \= localStorage.getItem('user\_role');  
       if (userRole) {  
           currentUserInfo.textContent \= \`Logged in as: ${userRole.charAt(0).toUpperCase() \+ userRole.slice(1)}\`;  
       } else {  
           currentUserInfo.textContent \= 'Not logged in';  
       }  
   }

   // Handle logout  
   document.getElementById('logout-btn').addEventListener('click', function() {  
       localStorage.removeItem('access\_token');  
       localStorage.removeItem('user\_role');  
       window.location.href \= '/login'; // Redirect to login page  
   });

   // Check auth status on load  
   document.addEventListener('DOMContentLoaded', () \=\> {  
       updateUserInfo();  
       if (\!localStorage.getItem('access\_token')) {  
           // Redirect to login if not authenticated, unless already on login/register page  
           if (\!window.location.pathname.startsWith('/login') && \!window.location.pathname.startsWith('/register')) {  
               window.location.href \= '/login';  
           }  
       }  
   });

   // Function to fetch and load HTML content dynamically  
   async function loadHtmlContent(pageName) {  
       contentArea.innerHTML \= \`  
           \<div class="d-flex justify-content-center align-items-center" style="min-height: 60vh;"\>  
               \<div class="spinner-border text-primary" role="status"\>  
                   \<span class="visually-hidden"\>Loading...\</span\>  
               \</div\>  
               \<p class="ms-3 text-muted"\>Loading ${pageName}...\</p\>  
           \</div\>  
       \`;  
       try {  
           const response \= await fetch(\`/static/html\_partials/${pageName}.html\`); // Assume partial HTML files  
           if (\!response.ok) throw new Error(\`Failed to load ${pageName}\`);  
           contentArea.innerHTML \= await response.text();  
           // After loading, attach event listeners specific to the loaded content  
           attachEventListeners(pageName);  
       } catch (error) {  
           console.error('Error loading content:', error);  
           contentArea.innerHTML \= \`\<div class="alert alert-danger" role="alert"\>Failed to load content: ${error.message}\</div\>\`;  
       }  
   }

   // Main content loader function  
   window.loadContent \= async function(page) {  
       console.log(\`Loading page: ${page}\`);  
       await loadHtmlContent(page);  
   };

   // Navigation event listeners  
   document.getElementById('nav-dashboard').addEventListener('click', (e) \=\> { e.preventDefault(); loadContent('dashboard'); });  
   document.getElementById('nav-products').addEventListener('click', (e) \=\> { e.preventDefault(); loadContent('products'); });  
   document.getElementById('nav-inventory').addEventListener('click', (e) \=\> { e.preventDefault(); loadContent('inventory'); });  
   document.getElementById('nav-orders').addEventListener('click', (e) \=\> { e.preventDefault(); loadContent('orders'); });

   // Function to attach event listeners for dynamically loaded content  
   function attachEventListeners(pageName) {  
       if (pageName \=== 'products') {  
           loadProductsTable();  
           const addProductForm \= document.getElementById('add-product-form');  
           if (addProductForm) {  
               addProductForm.addEventListener('submit', async function(e) {  
                   e.preventDefault();  
                   const name \= document.getElementById('product-name').value;  
                   const sku \= document.getElementById('product-sku').value;  
                   const price \= parseFloat(document.getElementById('product-price').value);  
                   const description \= document.getElementById('product-description').value;  
                   const dosage \= document.getElementById('product-dosage').value;

                   try {  
                       const response \= await fetch(\`${API\_BASE\_URL}/products/\`, {  
                           method: 'POST',  
                           headers: getAuthHeaders(),  
                           body: JSON.stringify({ name, sku, price, description, dosage })  
                       });  
                       const data \= await response.json();  
                       if (response.ok) {  
                           showMessage(data.message);  
                           addProductForm.reset();  
                           loadProductsTable(); // Reload table after adding  
                       } else {  
                           showMessage(data.message, false);  
                       }  
                   } catch (error) {  
                       console.error('Error adding product:', error);  
                       showMessage('An error occurred while adding product.', false);  
                   }  
               });  
           }  
       } else if (pageName \=== 'inventory') {  
           loadInventoryTable();  
           const addStockForm \= document.getElementById('add-stock-form');  
           if (addStockForm) {  
               addStockForm.addEventListener('submit', async function(e) {  
                   e.preventDefault();  
                   const productId \= document.getElementById('stock-product-id').value;  
                   const quantity \= parseInt(document.getElementById('stock-quantity').value);

                   try {  
                       const response \= await fetch(\`${API\_BASE\_URL}/inventory/\`, {  
                           method: 'POST',  
                           headers: getAuthHeaders(),  
                           body: JSON.stringify({ product\_id: productId, quantity: quantity })  
                       });  
                       const data \= await response.json();  
                       if (response.ok) {  
                           showMessage(data.message);  
                           addStockForm.reset();  
                           loadInventoryTable(); // Reload table  
                       } else {  
                           showMessage(data.message, false);  
                       }  
                   } catch (error) {  
                       console.error('Error adding stock:', error);  
                       showMessage('An error occurred while adding stock.', false);  
                   }  
               });  
           }  
       } else if (pageName \=== 'orders') {  
           loadOrdersTable();  
           const createOrderForm \= document.getElementById('create-order-form');  
           if (createOrderForm) {  
               createOrderForm.addEventListener('submit', async function(e) {  
                   e.preventDefault();  
                   const orderToId \= document.getElementById('order-to-id').value;  
                   // For simplicity, assuming one item per order for now, expand this for multiple items  
                   const productId \= document.getElementById('order-product-id').value;  
                   const quantity \= parseInt(document.getElementById('order-quantity').value);  
                   const items \= \[{ product\_id: productId, quantity: quantity }\];

                   try {  
                       const response \= await fetch(\`${API\_BASE\_URL}/orders/\`, {  
                           method: 'POST',  
                           headers: getAuthHeaders(),  
                           body: JSON.stringify({ order\_to\_id: orderToId, items: items })  
                       });  
                       const data \= await response.json();  
                       if (response.ok) {  
                           showMessage(data.message);  
                           createOrderForm.reset();  
                           loadOrdersTable(); // Reload table  
                       } else {  
                           showMessage(data.message, false);  
                       }  
                   } catch (error) {  
                       console.error('Error creating order:', error);  
                       showMessage('An error occurred while creating order.', false);  
                   }  
               });  
           }  
       } else if (pageName \=== 'dashboard') {  
           // Call Chart.js functions  
           renderStockChart();  
           renderSalesChart();  
       }  
   }

   // Example functions to fetch and populate tables (implement these fully)  
   async function loadProductsTable() {  
       const tableBody \= document.getElementById('products-table-body');  
       if (\!tableBody) return; // Exit if element not found

       tableBody.innerHTML \= '\<tr\>\<td colspan="6" class="text-center"\>Loading products...\</td\>\</tr\>';  
       try {  
           const response \= await fetch(\`${API\_BASE\_URL}/products/\`, { headers: getAuthHeaders() });  
           const products \= await response.json();  
           if (response.ok) {  
               tableBody.innerHTML \= ''; // Clear loading message  
               products.forEach(product \=\> {  
                   const row \= \`  
                       \<tr\>  
                           \<td\>${product.id}\</td\>  
                           \<td\>${product.name}\</td\>  
                           \<td\>${product.sku}\</td\>  
                           \<td\>${product.dosage || 'N/A'}\</td\>  
                           \<td\>$${product.price.toFixed(2)}\</td\>  
                           \<td\>${product.manufacturer}\</td\>  
                       \</tr\>  
                   \`;  
                   tableBody.insertAdjacentHTML('beforeend', row);  
               });  
           } else {  
               tableBody.innerHTML \= \`\<tr\>\<td colspan="6" class="text-center text-danger"\>${products.message || 'Failed to load products'}\</td\>\</tr\>\`;  
           }  
       } catch (error) {  
           console.error('Error loading products:', error);  
           tableBody.innerHTML \= \`\<tr\>\<td colspan="6" class="text-center text-danger"\>Error loading products.\</td\>\</tr\>\`;  
       }  
   }

   async function loadInventoryTable() {  
       const tableBody \= document.getElementById('inventory-table-body');  
       if (\!tableBody) return;

       tableBody.innerHTML \= '\<tr\>\<td colspan="6" class="text-center"\>Loading inventory...\</td\>\</tr\>';  
       const userRole \= localStorage.getItem('user\_role');  
       const userId \= JSON.parse(atob(localStorage.getItem('access\_token').split('.')\[1\])).identity.id; // Extract user ID from JWT (decode base64)

       try {  
           // Adjust API call based on user role and desired view  
           let url \= \`${API\_BASE\_URL}/inventory/${userId}\`; // Fetch current user's inventory  
           // Add logic here if Manufacturer/CFA needs to see other locations  
           // E.g., if userRole \=== 'manufacturer', fetch from other CFAs/SSs too by iterating  
           const response \= await fetch(url, { headers: getAuthHeaders() });  
           const inventoryRecords \= await response.json();

           if (response.ok) {  
               tableBody.innerHTML \= '';  
               if (inventoryRecords.length \=== 0\) {  
                   tableBody.innerHTML \= '\<tr\>\<td colspan="6" class="text-center"\>No inventory records found.\</td\>\</tr\>';  
               }  
               inventoryRecords.forEach(record \=\> {  
                   const row \= \`  
                       \<tr\>  
                           \<td\>${record.product\_name}\</td\>  
                           \<td\>${record.sku}\</td\>  
                           \<td\>${record.quantity}\</td\>  
                           \<td\>${record.location\_type.toUpperCase()}\</td\>  
                           \<td\>${record.location\_id}\</td\>  
                           \<td\>${new Date(record.last\_updated).toLocaleString()}\</td\>  
                       \</tr\>  
                   \`;  
                   tableBody.insertAdjacentHTML('beforeend', row);  
               });  
           } else {  
               tableBody.innerHTML \= \`\<tr\>\<td colspan="6" class="text-center text-danger"\>${inventoryRecords.message || 'Failed to load inventory'}\</td\>\</tr\>\`;  
           }  
       } catch (error) {  
           console.error('Error loading inventory:', error);  
           tableBody.innerHTML \= \`\<tr\>\<td colspan="6" class="text-center text-danger"\>Error loading inventory.\</td\>\</tr\>\`;  
       }  
   }

   async function loadOrdersTable() {  
       const tableBody \= document.getElementById('orders-table-body');  
       if (\!tableBody) return;

       tableBody.innerHTML \= '\<tr\>\<td colspan="7" class="text-center"\>Loading orders...\</td\>\</tr\>';  
       try {  
           const response \= await fetch(\`${API\_BASE\_URL}/orders/\`, { headers: getAuthHeaders() });  
           const orders \= await response.json();  
           if (response.ok) {  
               tableBody.innerHTML \= '';  
               if (orders.length \=== 0\) {  
                   tableBody.innerHTML \= '\<tr\>\<td colspan="7" class="text-center"\>No orders found.\</td\>\</tr\>';  
               }  
               orders.forEach(order \=\> {  
                   const itemsList \= order.items.map(item \=\> \`${item.product\_name} (${item.quantity})\`).join(', ');  
                   const row \= \`  
                       \<tr\>  
                           \<td\>${order.id}\</td\>  
                           \<td\>${order.order\_from}\</td\>  
                           \<td\>${order.order\_to}\</td\>  
                           \<td\>${itemsList}\</td\>  
                           \<td\>$${order.total\_amount.toFixed(2)}\</td\>  
                           \<td\>\<span class="badge ${getStatusBadgeClass(order.status)}"\>${order.status.toUpperCase()}\</span\>\</td\>  
                           \<td\>  
                               \<button class="btn btn-sm btn-info update-status-btn" data-order-id="${order.id}" data-current-status="${order.status}"\>Update Status\</button\>  
                           \</td\>  
                       \</tr\>  
                   \`;  
                   tableBody.insertAdjacentHTML('beforeend', row);  
               });  
               // Attach event listeners for update status buttons  
               document.querySelectorAll('.update-status-btn').forEach(button \=\> {  
                   button.addEventListener('click', async function() {  
                       const orderId \= this.dataset.orderId;  
                       const currentStatus \= this.dataset.currentStatus;  
                       // For simplicity, prompt for new status, in a real app use a modal/dropdown  
                       let newStatus \= prompt(\`Enter new status for Order ${orderId} (pending, processing, shipped, delivered, cancelled):\`, currentStatus);  
                       if (newStatus && \['pending', 'processing', 'shipped', 'delivered', 'cancelled'\].includes(newStatus.toLowerCase())) {  
                           try {  
                               const response \= await fetch(\`${API\_BASE\_URL}/orders/${orderId}/status\`, {  
                                   method: 'PUT',  
                                   headers: getAuthHeaders(),  
                                   body: JSON.stringify({ status: newStatus.toLowerCase() })  
                               });  
                               const data \= await response.json();  
                               if (response.ok) {  
                                   showMessage(data.message);  
                                   loadOrdersTable(); // Reload orders after update  
                               } else {  
                                   showMessage(data.message, false);  
                               }  
                           } catch (error) {  
                               console.error('Error updating order status:', error);  
                               showMessage('An error occurred while updating order status.', false);  
                           }  
                       } else if (newStatus) {  
                           showMessage('Invalid status entered.', false);  
                       }  
                   });  
               });  
           } else {  
               tableBody.innerHTML \= \`\<tr\>\<td colspan="7" class="text-center text-danger"\>${orders.message || 'Failed to load orders'}\</td\>\</tr\>\`;  
           }  
       } catch (error) {  
           console.error('Error loading orders:', error);  
           tableBody.innerHTML \= \`\<tr\>\<td colspan="7" class="text-center text-danger"\>Error loading orders.\</td\>\</tr\>\`;  
       }  
   }

   function getStatusBadgeClass(status) {  
       switch (status) {  
           case 'pending': return 'bg-warning text-dark';  
           case 'processing': return 'bg-info';  
           case 'shipped': return 'bg-primary';  
           case 'delivered': return 'bg-success';  
           case 'cancelled': return 'bg-danger';  
           default: return 'bg-secondary';  
       }  
   }

   // Helper to get dropdowns for product and user selections in forms  
   async function populateProductDropdown(dropdownId) {  
       const selectElement \= document.getElementById(dropdownId);  
       if (\!selectElement) return;  
       selectElement.innerHTML \= '\<option value=""\>Loading products...\</option\>';  
       try {  
           const response \= await fetch(\`${API\_BASE\_URL}/products/\`, { headers: getAuthHeaders() });  
           const products \= await response.json();  
           if (response.ok) {  
               selectElement.innerHTML \= '\<option value=""\>Select Product\</option\>';  
               products.forEach(product \=\> {  
                   selectElement.innerHTML \+= \`\<option value="${product.id}"\>${product.name} (SKU: ${product.sku})\</option\>\`;  
               });  
           } else {  
               selectElement.innerHTML \= '\<option value=""\>Error loading products\</option\>';  
           }  
       } catch (error) {  
           console.error('Error populating product dropdown:', error);  
           selectElement.innerHTML \= '\<option value=""\>Error loading products\</option\>';  
       }  
   }

   async function populateUserDropdown(dropdownId, allowedRoles) {  
       const selectElement \= document.getElementById(dropdownId);  
       if (\!selectElement) return;  
       selectElement.innerHTML \= '\<option value=""\>Loading users...\</option\>';  
       try {  
           // Note: A dedicated /api/users endpoint with appropriate role-based access would be needed  
           // For now, assuming you might have a way to fetch users or manually set them for demo  
           const dummyUsers \= \[  
               { id: 1, username: 'ManufacturerCo', role: 'manufacturer' },  
               { id: 2, username: 'CFA\_Distributor', role: 'cfa' },  
               { id: 3, username: 'SuperStockist\_East', role: 'super\_stockist' },  
               { id: 4, username: 'SuperStockist\_West', role: 'super\_stockist' }  
           \];

           selectElement.innerHTML \= '\<option value=""\>Select Recipient\</option\>';  
           dummyUsers.filter(user \=\> allowedRoles.includes(user.role)).forEach(user \=\> {  
               selectElement.innerHTML \+= \`\<option value="${user.id}"\>${user.username} (${user.role.toUpperCase()})\</option\>\`;  
           });

       } catch (error) {  
           console.error('Error populating user dropdown:', error);  
           selectElement.innerHTML \= '\<option value=""\>Error loading users\</option\>';  
       }  
   }

5. Chart.js Integration (app/static/js/charts.js):  
   Visualizing data on the dashboard.  
   // app/static/js/charts.js

   let stockChartInstance \= null;  
   let salesChartInstance \= null;

   // Function to render Stock Distribution Chart  
   async function renderStockChart() {  
       const ctx \= document.getElementById('stockChart');  
       if (\!ctx) return; // Exit if canvas not found

       // Destroy previous chart instance if it exists  
       if (stockChartInstance) {  
           stockChartInstance.destroy();  
       }

       try {  
           // Fetch inventory data (example: fetch all inventory or relevant ones for the current user)  
           // For simplicity, this example uses dummy data. In a real app, fetch from API.  
           const userRole \= localStorage.getItem('user\_role');  
           const userId \= JSON.parse(atob(localStorage.getItem('access\_token').split('.')\[1\])).identity.id; // Extract user ID from JWT

           let inventoryData \= \[\];  
           // Simulate fetching relevant inventory based on user role  
           if (userRole \=== 'manufacturer') {  
               // Manufacturer sees all inventory potentially  
               const response \= await fetch(\`${API\_BASE\_URL}/inventory/${userId}\`, { headers: getAuthHeaders() }); // This would need to be an aggregated endpoint  
               // For a real manufacturer view, you might query ALL inventory and aggregate by product  
               // Dummy data for now:  
               inventoryData \= \[  
                   { product\_name: 'PANSZ-DSR', quantity: 5000, location\_type: 'manufacturer' },  
                   { product\_name: 'MONTELU-LC', quantity: 3000, location\_type: 'manufacturer' },  
                   { product\_name: 'ZEKCLAV-DS', quantity: 2000, location\_type: 'cfa' },  
                   { product\_name: 'GLIMCUZ-M GP 1', quantity: 1500, location\_type: 'super\_stockist' },  
               \];  
           } else if (userRole \=== 'cfa') {  
               const response \= await fetch(\`${API\_BASE\_URL}/inventory/${userId}\`, { headers: getAuthHeaders() });  
               inventoryData \= await response.json(); // CFA sees their own inventory  
           } else if (userRole \=== 'super\_stockist') {  
               const response \= await fetch(\`${API\_BASE\_URL}/inventory/${userId}\`, { headers: getAuthHeaders() });  
               inventoryData \= await response.json(); // Super Stockist sees their own inventory  
           }

           const productLabels \= inventoryData.map(item \=\> \`${item.product\_name} (${item.location\_type.toUpperCase()})\`);  
           const quantities \= inventoryData.map(item \=\> item.quantity);

           stockChartInstance \= new Chart(ctx, {  
               type: 'bar',  
               data: {  
                   labels: productLabels,  
                   datasets: \[{  
                       label: 'Current Stock Quantity',  
                       data: quantities,  
                       backgroundColor: \[  
                           'rgba(255, 99, 132, 0.6)',  
                           'rgba(54, 162, 235, 0.6)',  
                           'rgba(255, 206, 86, 0.6)',  
                           'rgba(75, 192, 192, 0.6)',  
                           'rgba(153, 102, 255, 0.6)',  
                           'rgba(255, 159, 64, 0.6)'  
                       \],  
                       borderColor: \[  
                           'rgba(255, 99, 132, 1)',  
                           'rgba(54, 162, 235, 1)',  
                           'rgba(255, 206, 86, 1)',  
                           'rgba(75, 192, 192, 1)',  
                           'rgba(153, 102, 255, 1)',  
                           'rgba(255, 159, 64, 1)'  
                       \],  
                       borderWidth: 1  
                   }\]  
               },  
               options: {  
                   responsive: true,  
                   maintainAspectRatio: false,  
                   scales: {  
                       y: {  
                           beginAtZero: true,  
                           title: {  
                               display: true,  
                               text: 'Quantity'  
                           }  
                       },  
                       x: {  
                           title: {  
                               display: true,  
                               text: 'Product & Location'  
                           }  
                       }  
                   },  
                   plugins: {  
                       legend: {  
                           display: false  
                       },  
                       title: {  
                           display: true,  
                           text: 'Current Stock Distribution'  
                       }  
                   }  
               }  
           });  
       } catch (error) {  
           console.error('Error rendering stock chart:', error);  
           if (ctx) ctx.parentElement.innerHTML \= '\<p class="text-danger"\>Failed to load stock chart data.\</p\>';  
       }  
   }

   // Function to render Sales/Order Trends Chart  
   async function renderSalesChart() {  
       const ctx \= document.getElementById('salesChart');  
       if (\!ctx) return;

       // Destroy previous chart instance if it exists  
       if (salesChartInstance) {  
           salesChartInstance.destroy();  
       }

       try {  
           // Fetch order data  
           // For simplicity, using dummy data grouped by month  
           const salesData \= \[  
               { month: 'Jan', sales: 12000 },  
               { month: 'Feb', sales: 19000 },  
               { month: 'Mar', sales: 15000 },  
               { month: 'Apr', sales: 17000 },  
               { month: 'May', sales: 22000 },  
               { month: 'Jun', sales: 25000 }  
           \];

           const months \= salesData.map(d \=\> d.month);  
           const salesAmounts \= salesData.map(d \=\> d.sales);

           salesChartInstance \= new Chart(ctx, {  
               type: 'line',  
               data: {  
                   labels: months,  
                   datasets: \[{  
                       label: 'Monthly Sales (USD)',  
                       data: salesAmounts,  
                       fill: true,  
                       backgroundColor: 'rgba(75, 192, 192, 0.2)',  
                       borderColor: 'rgba(75, 192, 192, 1)',  
                       tension: 0.3,  
                       pointBackgroundColor: 'rgba(75, 192, 192, 1)',  
                       pointBorderColor: '\#fff',  
                       pointHoverBackgroundColor: '\#fff',  
                       pointHoverBorderColor: 'rgba(75, 192, 192, 1)'  
                   }\]  
               },  
               options: {  
                   responsive: true,  
                   maintainAspectRatio: false,  
                   scales: {  
                       y: {  
                           beginAtZero: true,  
                           title: {  
                               display: true,  
                               text: 'Sales Amount (USD)'  
                           }  
                       },  
                       x: {  
                           title: {  
                               display: true,  
                               text: 'Month'  
                           }  
                       }  
                   },  
                   plugins: {  
                       legend: {  
                           display: true  
                       },  
                       title: {  
                           display: true,  
                           text: 'Monthly Sales/Order Trends'  
                       }  
                   }  
               }  
           });  
       } catch (error) {  
           console.error('Error rendering sales chart:', error);  
           if (ctx) ctx.parentElement.innerHTML \= '\<p class="text-danger"\>Failed to load sales chart data.\</p\>';  
       }  
   }

6. Animated CSS (app/static/css/style.css):  
   Add subtle animations for a better user experience.  
   /\* app/static/css/style.css \*/

   body {  
       background-color: \#f8f9fa;  
       font-family: 'Inter', sans-serif;  
   }

   /\* Card hover effect \*/  
   .card {  
       transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;  
   }  
   .card:hover {  
       transform: translateY(-5px);  
       box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15) \!important;  
   }

   /\* Button hover effects \*/  
   .btn {  
       transition: all 0.3s ease;  
       position: relative;  
       overflow: hidden;  
   }  
   .btn:hover {  
       transform: translateY(-2px);  
   }  
   .btn-primary:hover {  
       box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); /\* Bootstrap focus ring \*/  
   }

   /\* Form control focus animation \*/  
   .form-control:focus {  
       border-color: \#86b7fe;  
       box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);  
       outline: 0;  
   }

   /\* Spinner animation (already provided by Bootstrap, but for custom effects) \*/  
   @keyframes fadeIn {  
       from { opacity: 0; }  
       to { opacity: 1; }  
   }  
   .fade-in-content {  
       animation: fadeIn 0.5s ease-out;  
   }

   /\* Table styling with subtle stripes \*/  
   .table-striped \> tbody \> tr:nth-of-type(odd) \> \* {  
       background-color: rgba(0, 0, 0, 0.03);  
   }  
   .table th {  
       background-color: \#e9ecef;  
   }  
   .table thead th {  
       border-bottom: 2px solid \#dee2e6;  
   }

   /\* Custom scrollbar for tables if they overflow on small screens \*/  
   .table-responsive {  
       overflow-x: auto;  
   }

   /\* Navbar styling \*/  
   .navbar {  
       background: linear-gradient(90deg, rgba(13,110,253,1) 0%, rgba(108,117,125,1) 100%);  
   }  
   .navbar-brand {  
       font-weight: bold;  
       text-shadow: 1px 1px 2px rgba(0,0,0,0.2);  
   }  
   .navbar-nav .nav-link {  
       color: rgba(255, 255, 255, 0.8);  
       transition: color 0.3s ease, transform 0.2s ease;  
   }  
   .navbar-nav .nav-link:hover {  
       color: \#fff;  
       transform: scale(1.05);  
   }

   /\* General rounded corners \*/  
   .rounded-lg { border-radius: 0.75rem \!important; }  
   .rounded-xl { border-radius: 1rem \!important; }  
   .shadow-lg { box-shadow: 0 1rem 3rem rgba(0,0,0,.175)\!important; }

7. HTML Partials for Dynamic Content (app/static/html\_partials/):  
   These files will contain the HTML for different sections (products, inventory, orders, dashboard), loaded dynamically by main.js.  
   * app/static/html\_partials/dashboard.html  
     \<div class="row mb-4"\>  
         \<div class="col-md-12"\>  
             \<h1 class="display-5 fw-bold text-center text-primary mb-4"\>Supply Chain Dashboard\</h1\>  
             \<p class="lead text-center text-muted"\>Real-time insights into your pharmaceutical supply chain.\</p\>  
         \</div\>  
     \</div\>

     \<div class="row mb-4"\>  
         \<\!-- Summary Cards \--\>  
         \<div class="col-md-4 mb-3"\>  
             \<div class="card text-white bg-info shadow-sm h-100 rounded-lg"\>  
                 \<div class="card-body p-4 d-flex align-items-center justify-content-between"\>  
                     \<div\>  
                         \<h5 class="card-title text-uppercase mb-0"\>Total Products\</h5\>  
                         \<p class="card-text fs-3 fw-bold" id="total-products-count"\>...\</p\>  
                     \</div\>  
                     \<i class="fas fa-box fa-3x opacity-50"\>\</i\> \<\!-- FontAwesome icon if available \--\>  
                 \</div\>  
             \</div\>  
         \</div\>  
         \<div class="col-md-4 mb-3"\>  
             \<div class="card text-white bg-warning shadow-sm h-100 rounded-lg"\>  
                 \<div class="card-body p-4 d-flex align-items-center justify-content-between"\>  
                     \<div\>  
                         \<h5 class="card-title text-uppercase mb-0"\>Pending Orders\</h5\>  
                         \<p class="card-text fs-3 fw-bold" id="pending-orders-count"\>...\</p\>  
                     \</div\>  
                     \<i class="fas fa-hourglass-half fa-3x opacity-50"\>\</i\>  
                 \</div\>  
             \</div\>  
         \</div\>  
         \<div class="col-md-4 mb-3"\>  
             \<div class="card text-white bg-success shadow-sm h-100 rounded-lg"\>  
                 \<div class="card-body p-4 d-flex align-items-center justify-content-between"\>  
                     \<div\>  
                         \<h5 class="card-title text-uppercase mb-0"\>Total Sales (M)\</h5\>  
                         \<p class="card-text fs-3 fw-bold" id="total-sales-amount"\>...\</p\>  
                     \</div\>  
                     \<i class="fas fa-dollar-sign fa-3x opacity-50"\>\</i\>  
                 \</div\>  
             \</div\>  
         \</div\>  
     \</div\>

     \<div class="row"\>  
         \<div class="col-lg-6 mb-4"\>  
             \<div class="card shadow-sm h-100 rounded-lg"\>  
                 \<div class="card-header bg-light rounded-top-lg"\>  
                     \<h5 class="mb-0"\>Stock Distribution Overview\</h5\>  
                 \</div\>  
                 \<div class="card-body"\>  
                     \<canvas id="stockChart" style="max-height: 400px;"\>\</canvas\>  
                 \</div\>  
             \</div\>  
         \</div\>  
         \<div class="col-lg-6 mb-4"\>  
             \<div class="card shadow-sm h-100 rounded-lg"\>  
                 \<div class="card-header bg-light rounded-top-lg"\>  
                     \<h5 class="mb-0"\>Monthly Sales Trends\</h5\>  
                 \</div\>  
                 \<div class="card-body"\>  
                     \<canvas id="salesChart" style="max-height: 400px;"\>\</canvas\>  
                 \</div\>  
             \</div\>  
         \</div\>  
     \</div\>  
     \<script\>  
         // Dummy data population for summary cards (replace with API calls)  
         document.getElementById('total-products-count').textContent \= '25';  
         document.getElementById('pending-orders-count').textContent \= '5';  
         document.getElementById('total-sales-amount').textContent \= '$1.2M';

         // Ensure charts are rendered when the dashboard partial is loaded  
         // These functions are defined in charts.js, which is loaded in base.html  
         // They are called from attachEventListeners('dashboard') in main.js  
         // renderStockChart();  
         // renderSalesChart();  
     \</script\>

   * app/static/html\_partials/products.html  
     \<div class="row mb-4"\>  
         \<div class="col-md-12"\>  
             \<h2 class="display-6 fw-bold text-primary mb-3"\>Product Management\</h2\>  
             \<p class="text-muted"\>Manage all pharmaceutical products available in the supply chain.\</p\>  
         \</div\>  
     \</div\>

     \<div class="card shadow-sm mb-4 rounded-lg"\>  
         \<div class="card-header bg-light rounded-top-lg"\>  
             \<h5 class="mb-0"\>Add New Product\</h5\>  
         \</div\>  
         \<div class="card-body"\>  
             \<form id="add-product-form"\>  
                 \<div class="row g-3"\>  
                     \<div class="col-md-6"\>  
                         \<label for="product-name" class="form-label"\>Product Name\</label\>  
                         \<input type="text" class="form-control" id="product-name" required\>  
                     \</div\>  
                     \<div class="col-md-6"\>  
                         \<label for="product-sku" class="form-label"\>SKU\</label\>  
                         \<input type="text" class="form-control" id="product-sku" required\>  
                     \</div\>  
                     \<div class="col-md-6"\>  
                         \<label for="product-price" class="form-label"\>Price\</label\>  
                         \<input type="number" step="0.01" class="form-control" id="product-price" required\>  
                     \</div\>  
                     \<div class="col-md-6"\>  
                         \<label for="product-dosage" class="form-label"\>Dosage (Optional)\</label\>  
                         \<input type="text" class="form-control" id="product-dosage"\>  
                     \</div\>  
                     \<div class="col-12"\>  
                         \<label for="product-description" class="form-label"\>Description (Optional)\</label\>  
                         \<textarea class="form-control" id="product-description" rows="3"\>\</textarea\>  
                     \</div\>  
                     \<div class="col-12 text-end"\>  
                         \<button type="submit" class="btn btn-primary"\>Add Product\</button\>  
                     \</div\>  
                 \</div\>  
             \</form\>  
         \</div\>  
     \</div\>

     \<div class="card shadow-sm rounded-lg"\>  
         \<div class="card-header bg-light rounded-top-lg"\>  
             \<h5 class="mb-0"\>Product List\</h5\>  
         \</div\>  
         \<div class="card-body"\>  
             \<div class="table-responsive"\>  
                 \<table class="table table-striped table-hover align-middle"\>  
                     \<thead\>  
                         \<tr\>  
                             \<th\>ID\</th\>  
                             \<th\>Name\</th\>  
                             \<th\>SKU\</th\>  
                             \<th\>Dosage\</th\>  
                             \<th\>Price\</th\>  
                             \<th\>Manufacturer\</th\>  
                         \</tr\>  
                     \</thead\>  
                     \<tbody id="products-table-body"\>  
                         \<\!-- Products will be loaded here by JavaScript \--\>  
                     \</tbody\>  
                 \</table\>  
             \</div\>  
         \</div\>  
     \</div\>  
     \<script\>  
         // Ensure product table is loaded when this partial is dynamically added  
         // loadProductsTable(); // Called from attachEventListeners('products') in main.js  
     \</script\>

   * app/static/html\_partials/inventory.html  
     \<div class="row mb-4"\>  
         \<div class="col-md-12"\>  
             \<h2 class="display-6 fw-bold text-primary mb-3"\>Inventory Management\</h2\>  
             \<p class="text-muted"\>Track stock levels at different locations (Manufacturer, CFA, Super Stockist).\</p\>  
         \</div\>  
     \</div\>

     \<div class="card shadow-sm mb-4 rounded-lg"\>  
         \<div class="card-header bg-light rounded-top-lg"\>  
             \<h5 class="mb-0"\>Add/Update Stock\</h5\>  
         \</div\>  
         \<div class="card-body"\>  
             \<form id="add-stock-form"\>  
                 \<div class="row g-3"\>  
                     \<div class="col-md-6"\>  
                         \<label for="stock-product-id" class="form-label"\>Product\</label\>  
                         \<select class="form-select" id="stock-product-id" required\>  
                             \<\!-- Products loaded by JS \--\>  
                         \</select\>  
                     \</div\>  
                     \<div class="col-md-6"\>  
                         \<label for="stock-quantity" class="form-label"\>Quantity\</label\>  
                         \<input type="number" class="form-control" id="stock-quantity" min="1" required\>  
                     \</div\>  
                     \<div class="col-12 text-end"\>  
                         \<button type="submit" class="btn btn-primary"\>Update Stock\</button\>  
                     \</div\>  
                 \</div\>  
             \</form\>  
         \</div\>  
     \</div\>

     \<div class="card shadow-sm rounded-lg"\>  
         \<div class="card-header bg-light rounded-top-lg"\>  
             \<h5 class="mb-0"\>Current Inventory Overview\</h5\>  
         \</div\>  
         \<div class="card-body"\>  
             \<div class="table-responsive"\>  
                 \<table class="table table-striped table-hover align-middle"\>  
                     \<thead\>  
                         \<tr\>  
                             \<th\>Product Name\</th\>  
                             \<th\>SKU\</th\>  
                             \<th\>Quantity\</th\>  
                             \<th\>Location Type\</th\>  
                             \<th\>Location ID\</th\>  
                             \<th\>Last Updated\</th\>  
                         \</tr\>  
                     \</thead\>  
                     \<tbody id="inventory-table-body"\>  
                         \<\!-- Inventory will be loaded here by JavaScript \--\>  
                     \</tbody\>  
                 \</table\>  
             \</div\>  
         \</div\>  
     \</div\>  
     \<script\>  
         // Populate product dropdown when this partial is loaded  
         // populateProductDropdown('stock-product-id'); // Called from attachEventListeners('inventory') in main.js  
         // loadInventoryTable(); // Called from attachEventListeners('inventory') in main.js  
     \</script\>

   * app/static/html\_partials/orders.html  
     \<div class="row mb-4"\>  
         \<div class="col-md-12"\>  
             \<h2 class="display-6 fw-bold text-primary mb-3"\>Order Management\</h2\>  
             \<p class="text-muted"\>Create new orders and track their status throughout the supply chain.\</p\>  
         \</div\>  
     \</div\>

     \<div class="card shadow-sm mb-4 rounded-lg"\>  
         \<div class="card-header bg-light rounded-top-lg"\>  
             \<h5 class="mb-0"\>Create New Order\</h5\>  
         \</div\>  
         \<div class="card-body"\>  
             \<form id="create-order-form"\>  
                 \<div class="row g-3"\>  
                     \<div class="col-md-6"\>  
                         \<label for="order-to-id" class="form-label"\>Order To (CFA/Manufacturer)\</label\>  
                         \<select class="form-select" id="order-to-id" required\>  
                             \<\!-- Users loaded by JS based on current user role \--\>  
                         \</select\>  
                     \</div\>  
                     \<div class="col-md-6"\>  
                         \<label for="order-product-id" class="form-label"\>Product\</label\>  
                         \<select class="form-select" id="order-product-id" required\>  
                             \<\!-- Products loaded by JS \--\>  
                         \</select\>  
                     \</div\>  
                     \<div class="col-md-6"\>  
                         \<label for="order-quantity" class="form-label"\>Quantity\</label\>  
                         \<input type="number" class="form-control" id="order-quantity" min="1" required\>  
                     \</div\>  
                     \<div class="col-12 text-end"\>  
                         \<button type="submit" class="btn btn-primary"\>Place Order\</button\>  
                     \</div\>  
                 \</div\>  
             \</form\>  
         \</div\>  
     \</div\>

     \<div class="card shadow-sm rounded-lg"\>  
         \<div class="card-header bg-light rounded-top-lg"\>  
             \<h5 class="mb-0"\>Order History\</h5\>  
         \</div\>  
         \<div class="card-body"\>  
             \<div class="table-responsive"\>  
                 \<table class="table table-striped table-hover align-middle"\>  
                     \<thead\>  
                         \<tr\>  
                             \<th\>Order ID\</th\>  
                             \<th\>From\</th\>  
                             \<th\>To\</th\>  
                             \<th\>Items\</th\>  
                             \<th\>Total Amount\</th\>  
                             \<th\>Status\</th\>  
                             \<th\>Actions\</th\>  
                         \</tr\>  
                     \</thead\>  
                     \<tbody id="orders-table-body"\>  
                         \<\!-- Orders will be loaded here by JavaScript \--\>  
                     \</tbody\>  
                 \</table\>  
             \</div\>  
         \</div\>  
     \</div\>  
     \<script\>  
         // Populate dropdowns and load orders when this partial is dynamically added  
         // populateProductDropdown('order-product-id');  
         // populateUserDropdown('order-to-id', \['cfa', 'manufacturer'\]); // Adjust roles based on current user's role  
         // loadOrdersTable(); // Called from attachEventListeners('orders') in main.js  
     \</script\>

*Note: Remember to create a login.html route in your Flask app to render the login.html template when accessing /login and similarly for /register.*

## **5\. Development Best Practices and Next Steps**

To make this the "best" system, consider these crucial aspects:

1. **Input Validation and Sanitization:**  
   * **Server-Side (Python):** Always validate and sanitize all incoming API request data. Use libraries like Marshmallow for schema validation. This prevents common vulnerabilities like SQL injection (though SQLAlchemy helps) and ensures data integrity.  
   * **Client-Side (JavaScript):** Perform basic validation for user experience (e.g., required fields, number formats). This reduces unnecessary server requests.  
2. **Security:**  
   * **Authentication:** JWT (JSON Web Tokens) with Flask-JWT-Extended is a good choice. Ensure tokens are stored securely (e.g., localStorage is okay for simple apps, but httpOnly cookies are preferred for production to mitigate XSS).  
   * **Authorization (Role-Based Access Control \- RBAC):** As demonstrated with role\_required decorator, strictly enforce what each user role can do.  
   * **Password Hashing:** Use Flask-Bcrypt (or similar) to hash passwords securely. Never store plain passwords.  
   * **CORS (Cross-Origin Resource Sharing):** If your frontend and backend run on different domains/ports, you'll need to configure CORS on the Flask side (e.g., Flask-CORS).  
   * **HTTPS:** Always deploy with HTTPS in production to encrypt data in transit.  
3. **Error Handling:**  
   * **API Errors:** Return meaningful HTTP status codes (400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict, 500 Internal Server Error) and clear JSON error messages.  
   * **Frontend Errors:** Implement try-catch blocks for all fetch API calls. Display user-friendly error messages in the UI.  
4. **Modularization and Service Layer:**  
   * Separate your code into logical modules: models (database schemas), api (route definitions), services (business logic), templates (frontend views), static (frontend assets).  
   * The services layer (app/services/) should contain the core business logic. API endpoints should call services, rather than directly interacting with models or complex logic. This makes your code more testable and organized.  
5. **Testing:**  
   * **Unit Tests:** Test individual functions, models, and API endpoints in isolation. Use Python's unittest or pytest.  
   * **Integration Tests:** Test interactions between different components (e.g., API calls hitting the database).  
   * Set up a tests/ directory and write comprehensive tests.  
6. **Performance and Scalability:**  
   * **Database Indexing:** As your SQLite database grows, add indexes to frequently queried columns (e.g., username, email, product\_id, order\_from\_id, order\_to\_id) to improve query performance. SQLAlchemy allows this in model definitions.  
   * **Pagination:** For large lists (products, orders, inventory), implement pagination in your API and frontend to avoid loading all data at once.  
   * **Asynchronous Operations:** For long-running tasks (e.g., complex reports, sending many notifications), consider using Celery with a message broker (like Redis or RabbitMQ) to offload these tasks from the main web server.  
   * **Caching:** Implement caching for frequently accessed, but infrequently changing data.  
   * **Database Choice:** While SQLite is good for development and small apps, consider PostgreSQL or MySQL for larger production deployments that require more robust concurrency and features.  
7. **Notifications:**  
   * **Email:** Use a Python library like smtplib or a third-party service (SendGrid, Mailgun) to send email notifications for order updates, low stock, etc.  
   * **In-App Notifications:** Implement a simple notification system within the frontend, perhaps using WebSockets for real-time updates (more advanced).  
8. **Deployment:**  
   * **WSGI Server:** Use a production-ready WSGI server like Gunicorn (for Flask) or Uvicorn (for FastAPI) to serve your Python application.  
   * **Reverse Proxy:** Use Nginx or Apache as a reverse proxy to handle static files, SSL termination, and load balancing.  
   * **Containerization (Docker):** Containerize your application using Docker. This ensures consistency across development, testing, and production environments. Provide a Dockerfile and docker-compose.yml.  
9. **Documentation:**  
   * **API Documentation:** Use tools like Swagger/OpenAPI (e.g., Flask-RESTX integrates Swagger UI) to document your API endpoints.  
   * **Code Comments:** Write clear and concise comments for complex logic, functions, and classes.  
   * **README:** Keep the main README.md updated with setup, usage, and key features.

By following these instructions and best practices, you can build a robust, secure, and user-friendly Supply Chain Management System that effectively serves the needs of manufacturers, CFAs, and super stockists.