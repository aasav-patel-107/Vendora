from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import ARRAY, JSONB,JSON
from sqlalchemy.ext.mutable import MutableList
from datetime import datetime
db = SQLAlchemy()

# All models go below here
# (Account, Vendor, Customer, Product, Order, OrderItem)



class Account(db.Model):
    __tablename__ = 'account'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    accountname = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(20))
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'Admin', 'Vendor', 'Account'


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), unique=True)
    account = db.relationship('Account', backref='admin_profile')


class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), unique=True)
    account = db.relationship('Account', backref='vendor_profile')
    products = db.relationship('Product', back_populates='vendor', cascade="all, delete-orphan")


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), unique=True)
    account = db.relationship('Account', backref='customer_profile')
    addresses = db.Column(MutableList.as_mutable(JSON), default=[])

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    product_name = db.Column(db.String(100))
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer, default=1)

    customer = db.relationship('Customer', backref='cart_items')
    product = db.relationship('Product')


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer, default=0)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))
    
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))
    vendor = db.relationship('Vendor', back_populates='products')


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
    shipping_address = db.Column(JSON)
    total_amount = db.Column(db.Float)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    customer = db.relationship('Customer', backref='orders')
    items = db.relationship('OrderItem', backref='order', cascade="all, delete-orphan")


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    product_name = db.Column(db.String(100))  # store name at purchase time
    quantity = db.Column(db.Integer)
    price = db.Column(db.Float)  # price at time of purchase

    product = db.relationship('Product')
