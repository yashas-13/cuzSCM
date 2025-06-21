from datetime import datetime
from app.extensions import db

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_from_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    total_amount = db.Column(db.Float, nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    order_from_user = db.relationship('User', foreign_keys=[order_from_id], backref=db.backref('placed_orders', lazy=True))
    order_to_user = db.relationship('User', foreign_keys=[order_to_id], backref=db.backref('received_orders', lazy=True))

    items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')

    def __repr__(self) -> str:
        return f'<Order {self.id} from {self.order_from_id} to {self.order_to_id} - Status: {self.status}>'

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product', backref=db.backref('order_items', lazy=True))
    quantity = db.Column(db.Integer, nullable=False)
    price_at_order = db.Column(db.Float, nullable=False)

    def __repr__(self) -> str:
        return f'<OrderItem {self.id} for Order {self.order_id}: {self.quantity} x {self.product.name}>'
