from flask import Flask, render_template, request, redirect, session, url_for,flash,make_response,render_template_string, jsonify, make_response
from xhtml2pdf import pisa
from io import BytesIO
from config import Config
from models import db, Account, Vendor, Customer, Product, Order, CartItem, OrderItem
from order_utils import create_order  
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import timedelta
from functools import wraps
import csv
import io
import os
from flask import Response
from flask_migrate import Migrate
import re



def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'account_id' not in session:
                flash('Please log in first.', 'warning')
                return redirect(url_for('login'))

            if role and session.get('role') != role:
                flash('Unauthorized access.', 'danger')
                return redirect(url_for('login'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Utility functions
def is_valid_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

def is_valid_password(password):
    # At least 6 characters, 1 digit, no spaces
    return len(password) >= 6 and re.search(r'\d', password) and ' ' not in password

def is_valid_phone(phone):
    return re.match(r'^\+?\d{10,15}$', phone)  # Accepts digits, optional +, 10-15 digits

def render_pdf_from_template(template_name, **context):
    html = render_template(template_name, **context)
    pdf_file = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf_file)
    if pisa_status.err:
        return None
    pdf_file.seek(0)
    return pdf_file

def enforce_single_default(addresses):
    seen = False
    for addr in addresses:
        if addr.get("default", False):
            if not seen:
                seen = True
            else:
                addr["default"] = False




app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = timedelta(minutes=30)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

@app.before_request
def create_tables():
    db.create_all()

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        phone = request.form['phone']
        email = request.form['email'].strip().lower()
        accountname = request.form['accountname']
        password = request.form['password']
        role = request.form['role']

        # Validations
        if not is_valid_email(email):
            flash("Invalid email format", "danger")
            return redirect('/register')
        if not is_valid_password(password):
            flash("Password must be at least 6 characters long, include a number, and no spaces", "danger")
            return redirect('/register')
        if not is_valid_phone(phone):
            flash("Invalid phone number format", "danger")
            return redirect('/register')
        if Account.query.filter_by(email=email).first():
            flash("Vendora:Email already registered", "danger")
            return redirect('/register')

        # Determine if Admin or PendingAdmin
        if role == "Admin":
            existing_admin = Account.query.filter_by(role='Admin').first()
            if existing_admin:
                role = "PendingAdmin"
                flash("Admin request submitted for approval", "info")
            else:
                flash("Registered as first Admin", "success")

        # Create Account
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        account = Account(phone=phone, accountname=accountname, email=email, password=hashed_password, role=role)
        db.session.add(account)
        db.session.commit()

        if role == "Vendor":
            db.session.add(Vendor(account_id=account.id))
            db.session.commit()
        
        if role == "Customer":
            db.session.add(Customer(account_id=account.id))
            db.session.commit()

        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')

        account = Account.query.filter_by(email=email).first()

        if account and check_password_hash(account.password, password):
            session.permanent = True
            session['account_id'] = account.id
            session['account_email'] = account.email    
            session['accountname'] = account.accountname
            session['role'] = account.role


            if account.role == 'Admin':
                return redirect('/admin')
            elif account.role == 'Vendor':
                return redirect('/vendor')
            elif account.role == 'Customer':
                return redirect('/customer')
        else:
            flash("Vendora:Enter valid credentials", "danger")
            return redirect("/login")

    return render_template('login.html')

@app.route('/admin')
@login_required(role='Admin')
def admin_dashboard():
    if session.get('role') != 'Admin':
        return redirect('/login')
    
    search = request.args.get('search', '').strip().lower()
    sort_by = request.args.get('sort_by', '')

    # --- Vendors ---
    vendor_query = Vendor.query.join(Account)

    if search:
        vendor_query = vendor_query.filter(
            db.or_(
                Account.accountname.ilike(f"%{search}%"),
                Account.email.ilike(f"%{search}%")
            )
        )

    if sort_by == 'name_asc':
        vendor_query = vendor_query.order_by(Account.accountname.asc())
    elif sort_by == 'name_desc':
        vendor_query = vendor_query.order_by(Account.accountname.desc())
    elif sort_by == 'email_asc':
        vendor_query = vendor_query.order_by(Account.email.asc())
    elif sort_by == 'email_desc':
        vendor_query = vendor_query.order_by(Account.email.desc())

    vendors = vendor_query.all()

    # --- Pending Admins ---
    pending_admin_query = Account.query.filter_by(role='PendingAdmin')

    if search:
        pending_admin_query = pending_admin_query.filter(
            db.or_(
                Account.accountname.ilike(f"%{search}%"),
                Account.email.ilike(f"%{search}%")
            )
        )

    if sort_by == 'name_asc':
        pending_admin_query = pending_admin_query.order_by(Account.accountname.asc())
    elif sort_by == 'name_desc':
        pending_admin_query = pending_admin_query.order_by(Account.accountname.desc())
    elif sort_by == 'email_asc':
        pending_admin_query = pending_admin_query.order_by(Account.email.asc())
    elif sort_by == 'email_desc':
        pending_admin_query = pending_admin_query.order_by(Account.email.desc())

    pending_admins = pending_admin_query.all()
    total_accounts = Account.query.filter(Account.role.in_(['Admin', 'Vendor', 'Customer'])).count()
    total_vendors = Account.query.filter_by(role='Vendor').count()
    total_products = Product.query.count()
    total_customers = Customer.query.count()
    vendors = Vendor.query.all()
    pending_admins = Account.query.filter_by(role='PendingAdmin').all()
    products = Product.query.all()

    return render_template(
        'admin_dashboard.html',
        total_accounts=total_accounts,
        total_vendors=total_vendors,
        total_products=total_products,
        vendors=vendors,
        pending_admins=pending_admins,
        products=products,
        total_customers=total_customers
        )


@app.route('/admin/approve_admin', methods=['POST'])
@login_required(role='Admin')
def approve_admin():
    account_id = request.form.get('account_id', type=int)
    account = Account.query.get(account_id)

    if account and account.role == 'PendingAdmin':
        account.role = 'Admin'
        db.session.commit()
        flash(f"Vendora: Approved admin request for {account.email}", "success")

    
    return redirect('/admin')


@app.route('/admin/deny_admin', methods=['POST'])
@login_required(role='Admin')
def deny_admin():
    account_id = request.form.get('account_id', type=int)
    account = Account.query.get(account_id)

    if account and account.role == 'PendingAdmin':
        db.session.delete(account)
        db.session.commit()
        flash(f"Vendora: Denied admin request from {account.email}", "warning")
    return redirect('/admin')

@app.route('/admin/vendor/<int:vendor_id>', methods=['GET', 'POST'])
@login_required(role='Admin')
def admin_view_vendor(vendor_id):
    vendor = Vendor.query.get_or_404(vendor_id)
    account = vendor.account
    products = Product.query.filter_by(vendor_id=vendor.id).all()
    search = request.args.get('search', '').strip().lower()
    sort_by = request.args.get('sort_by', '')

    query = Product.query.filter_by(vendor_id=vendor.id)

    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f"%{search}%"),
                Product.description.ilike(f"%{search}%")
            )
        )

    if sort_by == 'name_asc':
        query = query.order_by(Product.name.asc())
    elif sort_by == 'name_desc':
        query = query.order_by(Product.name.desc())
    elif sort_by == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price_desc':
        query = query.order_by(Product.price.desc())


    return render_template('admin_view_vendor.html', vendor=vendor, account=account, products=products,search=search,sort_by=sort_by)

@app.route('/admin/vendor/<int:vendor_id>/add_product', methods=['GET', 'POST'])
@login_required(role='Admin')
def admin_add_product_to_vendor(vendor_id):
    vendor = Vendor.query.get_or_404(vendor_id)
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price', type=float)
        quantity = request.form.get('quantity', type=int)

        product = Product(name=name, description=description, price=price, quantity=quantity, vendor_id=vendor.id)
        db.session.add(product)
        db.session.commit()
        flash("Product added for vendor", "success")
        return redirect(url_for('admin_view_vendor', vendor_id=vendor.id))

    return render_template('add_product.html', vendor=vendor)


@app.route('/admin/vendor/<int:vendor_id>/delete', methods=['POST'])
@login_required(role='Admin')
def admin_delete_vendor(vendor_id):
    vendor = Vendor.query.get_or_404(vendor_id)
    account = vendor.account
    Product.query.filter_by(vendor_id=vendor.id).delete()
    db.session.delete(vendor)
    db.session.delete(account)
    db.session.commit()
    flash("Vendor and all associated data deleted", "success")
    return redirect('/admin')



@app.route('/admin/add_vendor', methods=['POST'])
@login_required(role='Admin')
def add_vendor():
    email = request.form.get('email').strip().lower()
    accountname = request.form.get('accountname')
    phone = request.form.get('phone')
    password = request.form.get('password')

    # safety-check
    if not accountname:
        flash("Vendora:Account name is required", "danger")
        return redirect('/admin')

    # validations:
    if not email:
        flash("Vendora:Email is required", "danger")
        return redirect('/admin')

    if not is_valid_email(email):
        flash("Invalid email format", "danger")
        return redirect('/register')

    if not is_valid_password(password):
        flash("Password must be at least 6 characters long, include a number, and no spaces", "danger")
        return redirect('/register')

    if not is_valid_phone(phone):
        flash("Invalid phone number format", "danger")
        return redirect('/register')
    

    if Account.query.filter_by(email=email).first():
        flash("Vendor email already exists.", "warning")
        return redirect('/admin')

    hashed_pw = generate_password_hash(password)
    account = Account(email=email, accountname=accountname, phone=phone, password=hashed_pw, role='Vendor')
    db.session.add(account)
    db.session.commit()

    vendor = Vendor(account_id=account.id)
    db.session.add(vendor)
    db.session.commit()

    flash("Vendora: Vendor added successfully.", "success")
    return redirect('/admin')


@app.route('/admin/delete_vendor/<int:vendor_id>', methods=['POST'])
@login_required(role='Admin')
def delete_vendor(vendor_id):
    vendor = Vendor.query.get_or_404(vendor_id)
    account = Account.query.get(vendor.account_id)

    if not account or account.role != 'Vendor':
        flash("Vendora:This account is not a vendor.", "danger")
        return redirect('/admin')

    db.session.delete(vendor)
    db.session.delete(account)
    db.session.commit()

    flash("Vendora:Vendor and their products deleted successfully", "success")
    return redirect('/admin')

@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required(role='Admin')
def admin_edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = request.form.get('price', type=float)
        product.quantity = request.form.get('quantity', type=int)
        db.session.commit()
        flash("Vendora: Product updated successfully.", "success")
        return redirect('/admin')
    return render_template('edit_product.html', product=product)


@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required(role='Admin')
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash("Vendora: Product deleted successfully.", "success")
    return redirect('/admin')

@app.route('/admin/orders')
@login_required(role='Admin')
def admin_all_orders():
    search = request.args.get('search', '').strip().lower()
    status_filter = request.args.get('status', '')

    query = Order.query.join(Customer).join(Account)

    if search:
        query = query.filter(
            db.or_(
                Account.accountname.ilike(f"%{search}%"),
                Account.email.ilike(f"%{search}%")
            )
        )

    if status_filter:
        query = query.filter(Order.status == status_filter)

    orders = query.order_by(Order.date.desc()).all()

    return render_template(
        'admin_all_orders.html',
        orders=orders,
        search=search,
        status_filter=status_filter
    )


@app.route('/admin/update_order_status/<int:order_id>', methods=['POST'])
@login_required(role='Admin')
def admin_update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')

    if new_status in ['Pending', 'Shipped', 'Cancelled', 'Delivered']:
        order.status = new_status
        db.session.commit()
        flash(f"Order #{order.id} updated to {new_status}.", "success")
    else:
        flash("Invalid order status.", "danger")

    return redirect(url_for('admin_all_orders'))


@app.route('/admin/customers')
@login_required(role='Admin')
def admin_all_customers():
    search = request.args.get('search', '').strip().lower()
    sort_by = request.args.get('sort_by', '')

    query = Customer.query.join(Account)

    if search:
        query = query.filter(
            db.or_(
                Account.accountname.ilike(f"%{search}%"),
                Account.email.ilike(f"%{search}%")
            )
        )

    if sort_by == 'name_asc':
        query = query.order_by(Account.accountname.asc())
    elif sort_by == 'name_desc':
        query = query.order_by(Account.accountname.desc())
    elif sort_by == 'email_asc':
        query = query.order_by(Account.email.asc())
    elif sort_by == 'email_desc':
        query = query.order_by(Account.email.desc())

    customers = query.all()
    return render_template('admin_all_customers.html', customers=customers, search=search, sort_by=sort_by)


@app.route('/admin/products')
@login_required(role='Admin')
def admin_all_products():
    search = request.args.get('search', '').strip().lower()
    sort_by = request.args.get('sort_by', '')

    query = Product.query.join(Vendor).join(Account)

    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f"%{search}%"),
                Product.description.ilike(f"%{search}%")
            )
        )

    if sort_by == 'name_asc':
        query = query.order_by(Product.name.asc())
    elif sort_by == 'name_desc':
        query = query.order_by(Product.name.desc())
    elif sort_by == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price_desc':
        query = query.order_by(Product.price.desc())

    products = query.all()
    return render_template('admin_all_products.html', products=products, search=search, sort_by=sort_by)


@app.route('/admin/delete_customer/<int:customer_id>', methods=['POST'])
@login_required(role='Admin')
def admin_delete_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    account = customer.account

    # Optional: delete their orders too
    Order.query.filter_by(customer_id=customer.id).delete()

    db.session.delete(customer)
    db.session.delete(account)
    db.session.commit()

    flash("Vendora: Customer account deleted.", "success")
    return redirect('/admin/customers')

@app.route('/admin/export_orders')
@login_required(role='Admin')
def export_orders():
    orders = Order.query.order_by(Order.date.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow(['Order ID', 'Customer Name', 'Email', 'Date', 'Status', 'Product', 'Price', 'Quantity', 'Total'])

    for order in orders:
        customer = order.customer.account
        for item in order.items:
            product = item.product
            total = item.quantity * product.price
            writer.writerow([
                order.id,
                customer.accountname,
                customer.email,
                order.date.strftime('%Y-%m-%d %H:%M'),
                order.status,
                product.name,
                product.price,
                item.quantity,
                f"{total:.2f}"
            ])

    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=orders.csv"}
    )


@app.route('/admin/export_admins')
@login_required(role='Admin')
def export_admins():
    admins = Account.query.filter_by(role='Admin').all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Account Name', 'Email', 'Phone', 'Role'])

    for admin in admins:
        writer.writerow([admin.id, admin.accountname, admin.email, admin.phone, admin.role])

    output.seek(0)
    return Response(output, mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=admins.csv"})

@app.route('/admin/export_vendors')
@login_required(role='Admin')
def export_vendors():
    vendors = Vendor.query.join(Account).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Account Name', 'Email', 'Phone', 'Vendor ID'])

    for vendor in vendors:
        writer.writerow([
            vendor.account.id,
            vendor.account.accountname,
            vendor.account.email,
            vendor.account.phone,
            vendor.id
        ])

    output.seek(0)
    return Response(output, mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=vendors.csv"})

@app.route('/admin/export_customers')
@login_required(role='Admin')
def export_customers():
    customers = Customer.query.join(Account).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Account Name', 'Email', 'Phone', 'Customer ID'])

    for customer in customers:
        writer.writerow([
            customer.account.id,
            customer.account.accountname,
            customer.account.email,
            customer.account.phone,
            customer.id
        ])

    output.seek(0)
    return Response(output, mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=customers.csv"})


@app.route('/vendor')
@login_required(role='Vendor')
def vendor_dashboard():
    account = Account.query.get(session['account_id'])
    vendor = Vendor.query.filter_by(account_id=account.id).first()

    if not vendor:
        flash("Vendora: Vendor profile not found. Please contact Admin.", "danger")
        return redirect('/login')

    query = Product.query.filter_by(vendor_id=vendor.id)

    # --- Filter by search ---
    search = request.args.get('search')
    if search:
        query = query.filter(Product.name.ilike(f"%{search}%"))

    # --- Sort by selection ---
    sort_by = request.args.get('sort_by')
    if sort_by == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price_desc':
        query = query.order_by(Product.price.desc())
    elif sort_by == 'name_asc':
        query = query.order_by(Product.name.asc())
    elif sort_by == 'name_desc':
        query = query.order_by(Product.name.desc())

    products = query.all()
    total_accounts = Account.query.count()

    return render_template(
        'vendor_dashboard.html',
        products=products,
        total_accounts=total_accounts,
        search=search,
        sort_by=sort_by
    )


@app.route('/vendor/add_product', methods=['GET', 'POST'])
@login_required(role='Vendor')
def show_add_product_form():
    account = Account.query.get(session['account_id'])
    vendor = Vendor.query.filter_by(account_id=account.id).first()
    if not vendor:
        flash("Vendora:Vendor not found. Contact admin.", "danger")
        return redirect('/vendor')

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        quantity = request.form.get('quantity', type=int)

        product = Product(
            name=name,
            description=description,
            price=price,
            quantity=quantity,
            vendor_id=vendor.id
        )
        db.session.add(product)
        db.session.commit()
        flash("Vendora:Product added successfully!", "success")
        return redirect('/vendor')

    return render_template('add_product.html')


@app.route('/vendor/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required(role='Vendor')
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    account = Account.query.get(session['account_id'])
    vendor = Vendor.query.filter_by(account_id=account.id).first()
    if product.vendor_id != vendor.id:
        flash("Vendora:Unauthorized access to edit this product.", "danger")
        return redirect('/vendor')

    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = request.form['price']
        product.quantity = request.form.get('quantity', type=int)

        # # Handle image upload (optional)
        # image = request.files.get('image')
        # if image and image.filename:
        #     filename = secure_filename(image.filename)
        #     image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        #     image.save(image_path)
        #     product.image_filename = filename

        db.session.commit()
        flash("Vendora:Product updated successfully!", "success")
        return redirect('/vendor')
    return render_template('edit_product.html', product=product)

@app.route('/vendor/delete_product/<int:product_id>', methods=['POST'])
@login_required(role='Vendor')
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    account = Account.query.get(session['account_id'])
    vendor = Vendor.query.filter_by(account_id=account.id).first()
    if product.vendor_id != vendor.id:
        flash("Vendora:Unauthorized action.", "danger")
        return redirect('/vendor')

    # # Optionally delete image file from disk (optional)
    # if product.image_filename:
    #     try:
    #         os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename))
    #     except:
    #         pass  # File might not exist

    db.session.delete(product)
    db.session.commit()
    flash("Vendora:Product deleted successfully!", "success")
    return redirect('/vendor')

@app.route('/customer')
@login_required(role='Customer')
def customer_dashboard():
    search = request.args.get('search', '').strip().lower()
    sort_by = request.args.get('sort_by', '')

    query = Product.query.join(Vendor).join(Account)

    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f"%{search}%"),
                Product.description.ilike(f"%{search}%")
            )
        )

    if sort_by == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price_desc':
        query = query.order_by(Product.price.desc())

    products = query.all()

    return render_template('customer_dashboard.html', products=products, search=search, sort_by=sort_by)


@app.route('/product/<int:product_id>')
@login_required(role='Customer')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


@app.route('/customer/cart/add/<int:product_id>', methods=['POST'])
@login_required(role='Customer')
def add_to_cart(product_id):    
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()
    product = Product.query.get_or_404(product_id)

    max_allowed = min(20, product.quantity)

    existing = CartItem.query.filter_by(customer_id=customer.id, product_id=product.id).first()

    if existing:
        if existing.quantity < max_allowed:
            existing.quantity += 1
            flash("Product quantity increased in cart.", "success")
        else:
            flash(f"Maximum allowed quantity is {max_allowed}.", "warning")
    else:
        if max_allowed >= 1:
            new_item = CartItem(
                customer_id=customer.id,
                product_id=product.id,
                product_name=product.name,
                price=product.price,
                quantity=1
            )
            db.session.add(new_item)
            flash("Product added to cart", "success")
        else:
            flash("This product is out of stock.", "danger")

    db.session.commit()
    return redirect(request.referrer or url_for('customer_dashboard'))




@app.route('/customer/cart')
@login_required(role='Customer')
def view_cart():
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=session['account_id']).first_or_404()
    cart_items = CartItem.query.filter_by(customer_id=customer.id).order_by(CartItem.id.asc()).all()
    total_price = sum(item.price * item.quantity for item in cart_items)

    # 🚫 Stop browser from caching
    response = make_response(render_template('customer_cart.html', cart_items=cart_items, total_price=total_price))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/cart/count')
@login_required(role='Customer')
def get_cart_count():
    customer = Customer.query.filter_by(account_id=session['account_id']).first()
    count = sum(item.quantity for item in customer.cart_items)
    return {'count': count}



@app.route('/customer/cart/update/<int:product_id>', methods=['POST'])
@login_required(role='Customer')
def update_cart_quantity(product_id):
    action = request.form.get('action')
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()

    cart_item = CartItem.query.filter_by(customer_id=customer.id, product_id=product_id).first_or_404()
    product = Product.query.get_or_404(product_id)

    max_allowed = min(20, product.quantity)

    if action == "increase" and cart_item.quantity < max_allowed:
        cart_item.quantity += 1
    elif action == "decrease" and cart_item.quantity > 1:
        cart_item.quantity -= 1

    db.session.commit()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        cart_items = CartItem.query.filter_by(customer_id=customer.id).order_by(CartItem.id.asc()).all()
        total_price = sum(item.price * item.quantity for item in cart_items)
        return jsonify(updated_cart_html=render_template_string("""
            <div id="cart-container">
            {% if cart_items %}
                <table class="table table-striped">
                <thead class="table-dark">
                    <tr>
                    <th>Product</th>
                    <th>Price</th>
                    <th>Quantity</th>
                    <th>Subtotal</th>
                    <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in cart_items %}
                    <tr>
                        <td>{{ item.product_name }}</td>
                        <td>₹{{ item.price }}</td>
                        <td>
                        <div class="d-flex align-items-center gap-2" data-product-id="{{ item.product_id }}">
                            {% if item.quantity > 1 %}
                            <button class="btn btn-sm btn-outline-secondary update-qty-btn" data-action="decrease" data-product-id="{{ item.product_id }}">-</button>
                            {% else %}
                            <button class="btn btn-sm btn-outline-danger remove-btn" data-product-id="{{ item.product_id }}" title="Remove">🗑️</button>
                            {% endif %}
                            <span class="mx-2 fw-bold">{{ item.quantity }}</span>
                            <button class="btn btn-sm btn-outline-secondary update-qty-btn" data-action="increase" data-product-id="{{ item.product_id }}">+</button>
                        </div>
                        </td>
                        <td>₹{{ item.price * item.quantity }}</td>
                        <td>
                        <button class="btn btn-sm btn-danger remove-btn" data-product-id="{{ item.product_id }}">Remove</button>
                        </td>
                    </tr>
                    {% endfor %}
                    <tr class="table-light">
                    <td colspan="4" class="text-end fw-bold">Total:</td>
                    <td class="fw-bold text-success">₹{{ total_price }}</td>
                    </tr>
                </tbody>
                </table>
                <div class="d-flex justify-content-between align-items-center mt-4">
                <a href='{{ url_for("customer_dashboard") }}' class="btn btn-outline-primary">← Continue Shopping</a>
                <div>
                    <h4 class="text-success mb-3">Total: ₹{{ total_price }}</h4>
                    <button class="btn btn-success btn-lg">Proceed to Checkout</button>
                </div>
                </div>
            {% else %}
                <div class="text-center py-5">
                <div class="mb-4">
                    <i class="fas fa-shopping-cart fa-5x text-muted"></i>
                </div>
                <h4 class="text-muted mb-3">Your cart is empty</h4>
                <p class="text-muted mb-4">Add some products to get started!</p>
                <a href="{{ url_for('customer_dashboard') }}" class="btn btn-primary">Start Shopping</a>
                </div>
            {% endif %}
            </div>
            """, cart_items=cart_items, total_price=total_price))


    return redirect(url_for('view_cart'))


@app.route('/customer/cart/remove/<int:product_id>', methods=['POST'])
@login_required(role='Customer')
def remove_from_cart(product_id):
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()

    cart_item = CartItem.query.filter_by(customer_id=customer.id, product_id=product_id).first_or_404()
    db.session.delete(cart_item)
    db.session.commit()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        cart_items = CartItem.query.filter_by(customer_id=customer.id).order_by(CartItem.id.asc()).all()
        total_price = sum(item.price * item.quantity for item in cart_items)
        return jsonify(updated_cart_html=render_template_string("""
            <div id="cart-container">
            {% if cart_items %}
                <table class="table table-striped">
                <thead class="table-dark">
                    <tr>
                    <th>Product</th>
                    <th>Price</th>
                    <th>Quantity</th>
                    <th>Subtotal</th>
                    <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in cart_items %}
                    <tr>
                        <td>{{ item.product_name }}</td>
                        <td>₹{{ item.price }}</td>
                        <td>
                        <div class="d-flex align-items-center gap-2" data-product-id="{{ item.product_id }}">
                            {% if item.quantity > 1 %}
                            <button class="btn btn-sm btn-outline-secondary update-qty-btn" data-action="decrease" data-product-id="{{ item.product_id }}">-</button>
                            {% else %}
                            <button class="btn btn-sm btn-outline-danger remove-btn" data-product-id="{{ item.product_id }}" title="Remove">🗑️</button>
                            {% endif %}
                            <span class="mx-2 fw-bold">{{ item.quantity }}</span>
                            <button class="btn btn-sm btn-outline-secondary update-qty-btn" data-action="increase" data-product-id="{{ item.product_id }}">+</button>
                        </div>
                        </td>
                        <td>₹{{ item.price * item.quantity }}</td>
                        <td>
                        <button class="btn btn-sm btn-danger remove-btn" data-product-id="{{ item.product_id }}">Remove</button>
                        </td>
                    </tr>
                    {% endfor %}
                    <tr class="table-light">
                    <td colspan="4" class="text-end fw-bold">Total:</td>
                    <td class="fw-bold text-success">₹{{ total_price }}</td>
                    </tr>
                </tbody>
                </table>
                <div class="d-flex justify-content-between align-items-center mt-4">
                <a href='{{ url_for("customer_dashboard") }}' class="btn btn-outline-primary">← Continue Shopping</a>
                <div>
                    <h4 class="text-success mb-3">Total: ₹{{ total_price }}</h4>
                    <button class="btn btn-success btn-lg">Proceed to Checkout</button>
                </div>
                </div>
            {% else %}
                <div class="text-center py-5">
                <div class="mb-4">
                    <i class="fas fa-shopping-cart fa-5x text-muted"></i>
                </div>
                <h4 class="text-muted mb-3">Your cart is empty</h4>
                <p class="text-muted mb-4">Add some products to get started!</p>
                <a href="{{ url_for('customer_dashboard') }}" class="btn btn-primary">Start Shopping</a>
                </div>
            {% endif %}
            </div>
            """, cart_items=cart_items, total_price=total_price))

    return redirect(url_for('view_cart'))





@app.context_processor
def inject_cart_count():
    if 'account_id' in session:
        account_id = session['account_id']
        customer = Customer.query.filter_by(account_id=account_id).first()
        if customer:
            count = sum(item.quantity for item in customer.cart_items)
            return dict(cart_count=count)
    return dict(cart_count=0)


@app.route('/customer/orders')
@login_required(role='Customer')
def order_history():
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()

    # Get filter/sort params
    status_filter = request.args.get('status')
    sort_by = request.args.get('sort', 'created_at')
    sort_dir = request.args.get('direction', 'desc')

    query = Order.query.filter_by(customer_id=customer.id)

    if status_filter and status_filter != 'All':
        query = query.filter_by(status=status_filter)

    if sort_by == 'amount':
        sort_column = Order.total_amount
    else:
        sort_column = Order.created_at

    if sort_dir == 'asc':
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    orders = query.all()
    return render_template(
        'order_history.html',
        orders=orders,
        status_filter=status_filter,
        sort_by=sort_by,
        sort_dir=sort_dir
    )




@app.route('/customer/addresses', methods=['GET', 'POST'])
@login_required(role='Customer')
def manage_addresses():
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()

    if request.method == 'POST':
        mode = request.form.get('mode')
        index = int(request.form.get('index', -1))
        is_default = 'default' in request.form  # ✅ safe checkbox check

        if mode == 'delete' and index >= 0:
            customer.addresses.pop(index)

        elif mode == 'edit' and index >= 0:
            updated = {
                "address_name": request.form['address_name'],
                "address_line": request.form['address_line'],
                "city": request.form['city'],
                "state": request.form['state'],
                "zip": request.form['zip'],
                "country": request.form['country'],
                "default": is_default
            }
            if is_default:
                for addr in customer.addresses:
                    addr['default'] = False
            customer.addresses[index] = updated

        elif mode == 'add':
            new_address = {
                "address_name": request.form['address_name'],
                "address_line": request.form['address_line'],
                "city": request.form['city'],
                "state": request.form['state'],
                "zip": request.form['zip'],
                "country": request.form['country'],
                "default": is_default
            }
            if is_default:
                for addr in customer.addresses:
                    addr['default'] = False
            customer.addresses.append(new_address)
        
        enforce_single_default(customer.addresses)
        db.session.commit()
        return redirect(url_for('manage_addresses'))

    return render_template('customer_addresses.html', addresses=customer.addresses or [])


@app.route('/cart/checkout', methods=['GET', 'POST'])
@login_required(role='Customer')
def cart_checkout():
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()
    cart_items = CartItem.query.filter_by(customer_id=customer.id).all()
    addresses = customer.addresses

    if not cart_items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('view_cart'))

    if request.method == 'POST':
        selected_index = int(request.form.get('address_index', -1))
        if selected_index == -1 or selected_index >= len(addresses):
            flash("Please select a valid address.", "danger")
            return redirect(request.url)

        selected_address = addresses[selected_index]

        # Prepare item data for order
        item_data = [
            {
                "product_id": item.product_id,
                "product_name": item.product_name,
                "price": item.price,
                "quantity": item.quantity
            }
            for item in cart_items
        ]

        # Create order
        order = create_order(customer_id=customer.id, cart_items=item_data, shipping_address=selected_address)

        # Clear cart
        for item in cart_items:
            db.session.delete(item)
        db.session.commit()

        flash("Order placed successfully.", "success")
        return redirect(url_for('simulate_payment', order_id=order.id))

    return render_template("cart_checkout.html", cart_items=cart_items, addresses=addresses)


@app.route('/product/buy/<int:product_id>', methods=['GET', 'POST'])
@login_required(role='Customer')
def buy_now(product_id):
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        # Handle new address addition
        if 'add_address' in request.form:
            new_address = {
                "address_name": request.form['address_name'],
                "address_line": request.form['address_line'],
                "city": request.form['city'],
                "state": request.form['state'],
                "zip": request.form['zip'],
                "country": request.form['country'],
                "default": 'default' in request.form
            }
            if new_address["default"]:
                for addr in customer.addresses:
                    addr["default"] = False
            customer.addresses.append(new_address)
            db.session.commit()
            flash("New address added successfully.", "success")
            return redirect(request.url)
        
        # Inside buy_now() after validating address
        selected_address = customer.addresses[selected_index]

        # Create order for 1 item
        item_data = [{
            "product_id": product.id,
            "product_name": product.name,
            "price": product.price,
            "quantity": 1
        }]
        order = create_order(customer_id=customer.id, cart_items=item_data, shipping_address=selected_address)

        # Redirect to simulated payment
        return redirect(url_for('simulate_payment', order_id=order.id))


        # Handle order placement
        selected_index = int(request.form.get('address_index', -1))
        if selected_index == -1 or selected_index >= len(customer.addresses):
            flash("Please select a valid shipping address.", "warning")
            return redirect(request.url)

        selected_address = customer.addresses[selected_index]

        # Simulate single item as a cart item
        item_data = [{
            "product_id": product.id,
            "product_name": product.name,
            "price": product.price,
            "quantity": 1
        }]

        # Create order
        order = create_order(customer_id=customer.id, cart_items=item_data, shipping_address=selected_address)

        flash("Order placed successfully.", "success")
        return redirect(url_for('simulate_payment', order_id=order.id))

    return render_template('checkout_select_address.html', product=product, addresses=customer.addresses)


@app.route('/order/<int:order_id>/invoice')
@login_required(role='Customer')
def order_invoice(order_id):
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()
    order = Order.query.filter_by(id=order_id, customer_id=customer.id).first_or_404()

    return render_template('invoice.html', order=order, customer=customer)


@app.route('/order/<int:order_id>/payment', methods=['GET', 'POST'])
@login_required(role='Customer')
def simulate_payment(order_id):
    order = Order.query.get_or_404(order_id)

    if request.method == 'POST':
        # Simulate success or failure
        payment_success = request.form.get('payment_status') == 'success'
        if payment_success:
            order.status = 'Paid'
            db.session.commit()
            flash("Payment successful. Thank you!", "success")
            return redirect(url_for('order_invoice', order_id=order.id))
        else:
            order.status = 'Payment Failed'
            db.session.commit()
            flash("Payment failed. Please try again.", "danger")
            return redirect(url_for('simulate_payment', order_id=order.id))

    return render_template('simulate_payment.html', order=order)


@app.route('/order/<int:order_id>/invoice/download')
@login_required(role='Customer')
def download_invoice(order_id):
    account_id = session['account_id']
    customer = Customer.query.filter_by(account_id=account_id).first_or_404()
    order = Order.query.filter_by(id=order_id, customer_id=customer.id).first_or_404()

    pdf_file = render_pdf_from_template('invoice.html', order=order, customer=customer)
    if not pdf_file:
        flash("Failed to generate PDF.", "danger")
        return redirect(url_for('order_invoice', order_id=order.id))

    response = make_response(pdf_file.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=invoice_{order.id}.pdf'
    return response


@app.route('/logout')
def logout():
    session.clear()
    flash("Vendora:You have been logged out", "info")
    return redirect('/login')

if __name__ == '__main__':
    app.secret_key = Config.SECRET_KEY
    app.run(debug=True)

