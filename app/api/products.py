from flask import Blueprint, request, jsonify
from app.models.product import Product
from app.extensions import db
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from functools import wraps

products_bp = Blueprint('products', __name__)

def role_required(allowed_roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user_identity = get_jwt_identity()
            user_role = get_jwt().get('role')
            if user_role not in allowed_roles:
                return jsonify({'message': 'Access forbidden: Insufficient permissions'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@products_bp.route('/', methods=['POST'])
@role_required(['manufacturer'])
def add_product():
    data = request.get_json() or {}
    current_user_identity = get_jwt_identity()
    manufacturer_id = int(current_user_identity)

    if not all(key in data for key in ['name', 'sku', 'price']):
        return jsonify({'message': 'Missing product data'}), 400

    if Product.query.filter_by(sku=data['sku']).first():
        return jsonify({'message': 'Product with this SKU already exists'}), 409

    new_product = Product(
        name=data['name'],
        sku=data['sku'],
        description=data.get('description'),
        dosage=data.get('dosage'),
        price=data['price'],
        manufacturer_id=manufacturer_id
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added successfully', 'product_id': new_product.id}), 201

@products_bp.route('/', methods=['GET'])
@jwt_required()
def get_products():
    products = Product.query.all()
    return jsonify([
        {
            'id': p.id,
            'name': p.name,
            'sku': p.sku,
            'description': p.description,
            'dosage': p.dosage,
            'price': p.price,
            'manufacturer': p.manufacturer.username if p.manufacturer else 'N/A'
        } for p in products
    ]), 200
