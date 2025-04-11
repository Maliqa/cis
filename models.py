from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(150), nullable=False)
    brand = db.Column(db.String(150), nullable=False)
    type = db.Column(db.String(150), nullable=False)
    spesifikasi = db.Column(db.String(250), nullable=False)
    no_computer = db.Column(db.String(150), nullable=False)
    purchased_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(150), nullable=False)
    addition = db.Column(db.String(250), nullable=True)
    email_active = db.Column(db.Boolean, default=False)
