from flask import Blueprint, request, jsonify
from app.models.inventory import Inventory
from app.models.product import Product
from app.models.user import User
from app.extensions import db
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.api.products import role_required

inventory_bp = Blueprint('inventory', __name__)

@inventory_bp.route('/', methods=['POST'])
@role_required(['manufacturer', 'cfa', 'super_stockist'])
def add_stock():
    data = request.get_json() or {}
    current_user_identity = get_jwt_identity()
    user_id = int(current_user_identity)
    user_role = get_jwt().get('role')

    product_id = data.get('product_id')
    quantity = data.get('quantity')

    if not all([product_id, quantity]):
        return jsonify({'message': 'Missing product_id or quantity'}), 400
    if not isinstance(quantity, int) or quantity <= 0:
        return jsonify({'message': 'Quantity must be a positive integer'}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    inventory_record = Inventory.query.filter_by(
        product_id=product_id,
        location_id=user_id,
        location_type=user_role
    ).first()

    if inventory_record:
        inventory_record.quantity += quantity
    else:
        inventory_record = Inventory(
            product_id=product_id,
            location_type=user_role,
            location_id=user_id,
            quantity=quantity
        )
        db.session.add(inventory_record)

    db.session.commit()
    return jsonify({'message': 'Stock updated successfully', 'current_quantity': inventory_record.quantity}), 200

@inventory_bp.route('/<int:location_id>', methods=['GET'])
@jwt_required()
def get_inventory_by_location(location_id):
    current_user_identity = get_jwt_identity()
    requester_id = int(current_user_identity)
    requester_role = get_jwt().get('role')

    if requester_id != location_id:
        target_user = User.query.get(location_id)
        if not target_user:
            return jsonify({'message': 'Location user not found'}), 404
        if requester_role == 'manufacturer' and target_user.role in ['cfa', 'super_stockist']:
            pass
        elif requester_role == 'cfa' and target_user.role == 'super_stockist':
            pass
        else:
            return jsonify({'message': 'Access forbidden: Not authorized to view this inventory'}), 403

    inventory_records = Inventory.query.filter_by(location_id=location_id).all()
    return jsonify([
        {
            'product_id': inv.product.id,
            'product_name': inv.product.name,
            'sku': inv.product.sku,
            'quantity': inv.quantity,
            'location_type': inv.location_type,
            'location_id': inv.location_id,
            'last_updated': inv.last_updated.isoformat()
        } for inv in inventory_records
    ]), 200
