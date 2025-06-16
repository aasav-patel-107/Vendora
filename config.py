import os

class Config:
    SECRET_KEY = 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:admin@localhost:1234/demo_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False