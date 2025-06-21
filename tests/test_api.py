import json
import pytest
from app import create_app
from app.extensions import db
from app.config import Config
from app.models import User, Product, Inventory, Order


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def register(client, username, email, password, role):
    return client.post('/api/auth/register', json={
        'username': username,
        'email': email,
        'password': password,
        'role': role
    })

def login(client, username, password):
    return client.post('/api/auth/login', json={
        'username': username,
        'password': password
    })

def auth_headers(token):
    return {'Authorization': f'Bearer {token}'}


def test_full_flow(client):
    # Register users
    register(client, 'manu', 'manu@example.com', 'pass', 'manufacturer')
    register(client, 'cfa', 'cfa@example.com', 'pass', 'cfa')
    register(client, 'ss', 'ss@example.com', 'pass', 'super_stockist')

    # Login
    resp = login(client, 'manu', 'pass')
    manu_token = resp.get_json()['access_token']
    resp = login(client, 'cfa', 'pass')
    cfa_token = resp.get_json()['access_token']
    resp = login(client, 'ss', 'pass')
    ss_token = resp.get_json()['access_token']

    # Add product by manufacturer
    resp = client.post('/api/products/', json={
        'name': 'Prod1',
        'sku': 'SKU1',
        'price': 10.0
    }, headers=auth_headers(manu_token))
    assert resp.status_code == 201
    product_id = resp.get_json()['product_id']

    # Add stock by manufacturer
    resp = client.post('/api/inventory/', json={
        'product_id': product_id,
        'quantity': 100
    }, headers=auth_headers(manu_token))
    assert resp.status_code == 200

    # Manufacturer requests inventory of CFA (allowed)
    resp = client.get('/api/inventory/2', headers=auth_headers(manu_token))
    assert resp.status_code == 200

    # CFA requests inventory of manufacturer (should be forbidden)
    resp = client.get('/api/inventory/1', headers=auth_headers(cfa_token))
    assert resp.status_code == 403

    # CFA creates order to manufacturer
    resp = client.post('/api/orders/', json={
        'order_to_id': 1,
        'items': [{'product_id': product_id, 'quantity': 5}]
    }, headers=auth_headers(cfa_token))
    assert resp.status_code == 201
    order_id = resp.get_json()['order_id']

    # Manufacturer ships order
    resp = client.put(f'/api/orders/{order_id}/status', json={
        'status': 'shipped'
    }, headers=auth_headers(manu_token))
    assert resp.status_code == 200

    # Super stockist cannot update order (should be forbidden)
    resp = client.put(f'/api/orders/{order_id}/status', json={
        'status': 'delivered'
    }, headers=auth_headers(ss_token))
    assert resp.status_code == 403

    # Get orders for CFA
    resp = client.get('/api/orders/', headers=auth_headers(cfa_token))
    assert resp.status_code == 200
    orders = resp.get_json()
    assert len(orders) == 1
