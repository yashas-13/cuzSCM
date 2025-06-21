from flask import Blueprint, request, jsonify
from app.models.order import Order, OrderItem
from app.models.product import Product
from app.models.inventory import Inventory
from app.models.user import User
from app.extensions import db
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.api.products import role_required

orders_bp = Blueprint('orders', __name__)

@orders_bp.route('/', methods=['POST'])
@role_required(['super_stockist', 'cfa'])
def create_order():
    data = request.get_json() or {}
    current_user_identity = get_jwt_identity()
    order_from_id = int(current_user_identity)
    order_from_role = get_jwt().get('role')

    order_to_id = data.get('order_to_id')
    items = data.get('items')
    if not all([order_to_id, items]) or not isinstance(items, list):
        return jsonify({'message': 'Missing order_to_id or items list'}), 400

    order_to_user = User.query.get(order_to_id)
    if not order_to_user:
        return jsonify({'message': 'Recipient user not found'}), 404

    if order_from_role == 'super_stockist' and order_to_user.role != 'cfa':
        return jsonify({'message': 'Super Stockist can only order from CFA'}), 403
    elif order_from_role == 'cfa' and order_to_user.role != 'manufacturer':
        return jsonify({'message': 'CFA can only order from Manufacturer'}), 403
    elif order_from_role == 'manufacturer':
        return jsonify({'message': 'Manufacturer cannot place orders from this interface'}), 403

    new_order = Order(
        order_from_id=order_from_id,
        order_to_id=order_to_id,
        status='pending',
        total_amount=0.0
    )
    db.session.add(new_order)
    db.session.flush()

    calculated_total = 0.0
    for item_data in items:
        product = Product.query.get(item_data['product_id'])
        if not product:
            db.session.rollback()
            return jsonify({'message': f"Product with ID {item_data['product_id']} not found"}), 404

        source_inventory = Inventory.query.filter_by(
            product_id=product.id,
            location_id=order_to_id,
            location_type=order_to_user.role
        ).first()
        if not source_inventory or source_inventory.quantity < item_data['quantity']:
            db.session.rollback()
            available = source_inventory.quantity if source_inventory else 0
            return jsonify({'message': f'Insufficient stock for {product.name} at {order_to_user.username}\'s location. Available: {available}'}), 400

        order_item = OrderItem(
            order_id=new_order.id,
            product_id=product.id,
            quantity=item_data['quantity'],
            price_at_order=product.price
        )
        db.session.add(order_item)
        calculated_total += product.price * item_data['quantity']

    new_order.total_amount = calculated_total
    db.session.commit()

    return jsonify({'message': 'Order placed successfully', 'order_id': new_order.id, 'total_amount': new_order.total_amount}), 201

@orders_bp.route('/<int:order_id>/status', methods=['PUT'])
@role_required(['manufacturer', 'cfa'])
def update_order_status(order_id):
    data = request.get_json() or {}
    new_status = data.get('status')
    current_user_identity = get_jwt_identity()
    user_id = int(current_user_identity)
    user_role = get_jwt().get('role')

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'message': 'Order not found'}), 404

    if order.order_to_id != user_id or order.order_to_user.role != user_role:
        return jsonify({'message': 'Access forbidden: You are not authorized to update this order'}), 403

    allowed_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
    if new_status not in allowed_statuses:
        return jsonify({'message': 'Invalid status provided'}), 400

    if new_status == 'shipped' and order.status != 'shipped':
        for item in order.items:
            inventory = Inventory.query.filter_by(
                product_id=item.product_id,
                location_id=order.order_to_id,
                location_type=order.order_to_user.role
            ).first()
            if inventory and inventory.quantity >= item.quantity:
                inventory.quantity -= item.quantity
            else:
                db.session.rollback()
                return jsonify({'message': f'Failed to update order status. Insufficient stock for {item.product.name}'}), 400

    order.status = new_status
    db.session.commit()
    return jsonify({'message': f'Order {order_id} status updated to {new_status}'}), 200

@orders_bp.route('/', methods=['GET'])
@jwt_required()
def get_orders():
    current_user_identity = get_jwt_identity()
    user_id = int(current_user_identity)
    user_role = get_jwt().get('role')

    if user_role == 'manufacturer':
        orders = Order.query.filter_by(order_to_id=user_id).all()
    elif user_role == 'cfa':
        orders = Order.query.filter(
            (Order.order_from_id == user_id) | (Order.order_to_id == user_id)
        ).all()
    elif user_role == 'super_stockist':
        orders = Order.query.filter_by(order_from_id=user_id).all()
    else:
        orders = []

    result = []
    for order in orders:
        items_data = [
            {
                'product_id': item.product.id,
                'product_name': item.product.name,
                'quantity': item.quantity,
                'price_at_order': item.price_at_order
            } for item in order.items
        ]
        result.append({
            'id': order.id,
            'order_from': order.order_from_user.username,
            'order_to': order.order_to_user.username,
            'status': order.status,
            'total_amount': order.total_amount,
            'created_at': order.created_at.isoformat(),
            'updated_at': order.updated_at.isoformat(),
            'items': items_data
        })
    return jsonify(result), 200
