from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, DateField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
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
    email_active = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class InventoryForm(FlaskForm):
    nama = StringField('Nama', validators=[DataRequired()])
    brand = StringField('Brand', validators=[DataRequired()])
    type = StringField('Type', validators=[DataRequired()])
    spesifikasi = TextAreaField('Spesifikasi', validators=[DataRequired()])
    no_computer = StringField('No. Computer', validators=[DataRequired()])
    purchased_date = DateField('Purchased Date', format='%Y-%m-%d', validators=[DataRequired()])
    status = StringField('Status', validators=[DataRequired()])
    addition = TextAreaField('Addition')
    email_active = TextAreaField('Email Active')
    submit = SubmitField('Submit')

@app.route('/')
@login_required
def inventory():
    search_query = request.args.get('search', '')
    if search_query:
        items = Inventory.query.filter(
            (Inventory.nama.ilike(f'%{search_query}%')) |
            (Inventory.brand.ilike(f'%{search_query}%')) |
            (Inventory.type.ilike(f'%{search_query}%')) |
            (Inventory.spesifikasi.ilike(f'%{search_query}%')) |
            (Inventory.no_computer.ilike(f'%{search_query}%')) |
            (Inventory.status.ilike(f'%{search_query}%')) |
            (Inventory.addition.ilike(f'%{search_query}%'))
        ).all()
    else:
        items = Inventory.query.all()
    
    current_date = datetime.utcnow()
    for item in items:
        if (current_date - item.purchased_date) > timedelta(days=5*365):
            item.blink = True
        else:
            item.blink = False
    return render_template('inventory.html', items=items, search_query=search_query)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_inventory():
    form = InventoryForm()
    if form.validate_on_submit():
        new_item = Inventory(
            nama=form.nama.data,
            brand=form.brand.data,
            type=form.type.data,
            spesifikasi=form.spesifikasi.data,
            no_computer=form.no_computer.data,
            purchased_date=form.purchased_date.data,
            status=form.status.data,
            addition=form.addition.data,
            email_active=form.email_active.data
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Inventory item added successfully!', 'success')
        return redirect(url_for('inventory'))
    return render_template('add_inventory.html', form=form)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_inventory(id):
    item = Inventory.query.get_or_404(id)
    form = InventoryForm(obj=item)
    if form.validate_on_submit():
        item.nama = form.nama.data
        item.brand = form.brand.data
        item.type = form.type.data
        item.spesifikasi = form.spesifikasi.data
        item.no_computer = form.no_computer.data
        item.purchased_date = form.purchased_date.data
        item.status = form.status.data
        item.addition = form.addition.data
        item.email_active = form.email_active.data
        db.session.commit()
        flash('Inventory item updated successfully!', 'success')
        return redirect(url_for('inventory'))
    return render_template('edit_inventory.html', form=form)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_inventory(id):
    item = Inventory.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Inventory item deleted successfully!', 'success')
    return redirect(url_for('inventory'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('inventory'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/export_pdf')
@login_required
def export_pdf():
    items = Inventory.query.all()
    pdf_path = 'inventory_report.pdf'
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    c.drawString(100, height - 50, "Inventory Report")
    y = height - 100
    for item in items:
        c.drawString(50, y, f"Nama: {item.nama}")
        c.drawString(50, y - 20, f"Brand: {item.brand}")
        c.drawString(50, y - 40, f"Type: {item.type}")
        c.drawString(50, y - 60, f"Spesifikasi: {item.spesifikasi}")
        c.drawString(50, y - 80, f"No. Computer: {item.no_computer}")
        c.drawString(50, y - 100, f"Purchased Date: {item.purchased_date.strftime('%Y-%m-%d')}")
        c.drawString(50, y - 120, f"Status: {item.status}")
        c.drawString(50, y - 140, f"Addition: {item.addition}")
        c.drawString(50, y - 160, f"Email Active: {item.email_active}")
        y -= 180
        if y < 50:
            c.showPage()
            y = height - 50
    c.save()
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
   with app.app_context():
    db.create_all()
    app.run(debug=True)
