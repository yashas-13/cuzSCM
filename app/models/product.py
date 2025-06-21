from datetime import datetime
from app.extensions import db

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    sku = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    dosage = db.Column(db.String(50))
    price = db.Column(db.Float, nullable=False)
    manufacturer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    manufacturer = db.relationship('User', backref=db.backref('products', lazy=True))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        return f'<Product {self.name}>'
