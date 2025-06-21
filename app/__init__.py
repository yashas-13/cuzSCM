import os
from flask import Flask
from app.config import Config
from app.extensions import db, migrate, bcrypt, jwt
from app.api import auth_bp, products_bp, inventory_bp, orders_bp
from dotenv import load_dotenv

load_dotenv()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(products_bp, url_prefix='/api/products')
    app.register_blueprint(inventory_bp, url_prefix='/api/inventory')
    app.register_blueprint(orders_bp, url_prefix='/api/orders')

    from app import models  # noqa: F401

    @app.route('/')
    def index():
        return "Welcome to the Supply Chain Management System!"

    return app
