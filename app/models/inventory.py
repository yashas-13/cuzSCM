from datetime import datetime
from app.extensions import db

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product', backref=db.backref('inventory_records', lazy=True))
    location_type = db.Column(db.String(50), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location_entity = db.relationship('User', backref=db.backref('inventory_at_location', lazy=True))
    quantity = db.Column(db.Integer, nullable=False, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        return f'<Inventory {self.product.name} at {self.location_type}-{self.location_id}: {self.quantity}>'
