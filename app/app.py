import os
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, g, send_from_directory, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flasgger import Swagger
import time
import uuid
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Swagger configuration
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/swagger/"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "CircuitCart API",
        "description": "E-commerce API with user authentication and product management",
        "contact": {
            "responsibleOrganization": "CircuitCart",
            "responsibleDeveloper": "CircuitCart Team",
            "email": "support@circuitcart.com",
            "url": "https://circuitcart.com",
        },
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
        }
    },
    "security": [
        {
            "Bearer": []
        }
    ]
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_upload_folder():
    """Ensure the upload folder exists"""
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Database Connection ---

def get_db_connection():
    """Gets a new PostgreSQL connection."""
    if 'db_conn' not in g:
        max_retries = 3
        for attempt in range(max_retries):
            try:
                g.db_conn = psycopg2.connect(
                    host=os.environ.get('DB_HOST'),
                    dbname=os.environ.get('DB_NAME'),
                    user=os.environ.get('DB_USER'),
                    password=os.environ.get('DB_PASS'),
                    connect_timeout=10
                )
                print(f"✅ Connected to database: {os.environ.get('DB_HOST')}")
                break
            except Exception as e:
                print(f"❌ Database connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    raise
    return g.db_conn

@app.teardown_appcontext
def close_connection(exception):
    """Closes the DB connection at the end of the request."""
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        db_conn.close()

def init_database():
    """
    Initializes the database with tables and sample data.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create 'users' table if not exists
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'seller', 'admin')),
            is_approved BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create 'products' table if not exists
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            product_id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            category TEXT,
            image_url TEXT,
            created_by INTEGER REFERENCES users(user_id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create 'inventory' table if not exists
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            product_id INTEGER PRIMARY KEY,
            quantity INTEGER NOT NULL,
            FOREIGN KEY (product_id) REFERENCES products (product_id)
        )
        ''')

        # Check if admin user exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            print("👑 Creating default admin user...")
            # Create default admin user (password: admin123)
            admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            cursor.execute("""
                INSERT INTO users (email, password_hash, first_name, last_name, role, is_approved)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, ('admin@circuitcart.com', admin_password, 'Admin', 'User', 'admin', True))
            print("✅ Default admin user created: admin@circuitcart.com / admin123")

        # Check if products table is empty
        cursor.execute("SELECT COUNT(*) FROM products")
        count = cursor.fetchone()[0]
        
        if count == 0:
            print("📦 Inserting sample products...")
            # Get admin user ID
            cursor.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
            admin_id = cursor.fetchone()[0]
            
            # Sample products
            products_data = [
                ('Pro Laptop', 'A 16-inch high-performance laptop for professionals.', 1200.00, 'Electronics', '/static/p1.png', admin_id),
                ('Classic Coffee Mug', 'A sturdy 12oz ceramic mug, dishwasher safe.', 15.50, 'Homeware', '/static/p2.png', admin_id),
                ('Wireless Mouse', 'Ergonomic mouse with 8-button layout and 2-year battery life.', 75.00, 'Electronics', '/static/p3.png', admin_id),
                ('Cotton T-Shirt', '100% premium soft cotton. Pre-shrunk and tagless.', 20.00, 'Apparel', '/static/p4.png', admin_id),
                ('Running Shoes', 'Lightweight and breathable. Perfect for road running.', 89.99, 'Apparel', '/static/p5.png', admin_id)
            ]
            
            cursor.executemany("INSERT INTO products (name, description, price, category, image_url, created_by) VALUES (%s, %s, %s, %s, %s, %s)", products_data)
            
            # Get the new product IDs
            cursor.execute("SELECT product_id FROM products ORDER BY product_id ASC;")
            product_ids = [row[0] for row in cursor.fetchall()]

            # Sample inventory
            inventory_data = [
                (product_ids[0], 5),
                (product_ids[1], 100),
                (product_ids[2], 0),
                (product_ids[3], 20),
                (product_ids[4], 9)
            ]
            cursor.executemany("INSERT INTO inventory (product_id, quantity) VALUES (%s, %s)", inventory_data)
            
            conn.commit()
            print("✅ Database initialized with sample data")
        else:
            print("✅ Database already contains data")
            
        cursor.close()
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")

# Initialize database and upload folder when app starts
with app.app_context():
    try:
        init_database()
        ensure_upload_folder()
    except Exception as e:
        print(f"❌ Initial setup failed: {e}")

# --- Authentication & Authorization Decorators ---

def admin_required(fn):
    """Decorator to require admin role"""
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE user_id = %s", (current_user_id,))
        user = cursor.fetchone()
        cursor.close()
        
        if not user or user[0] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def seller_required(fn):
    """Decorator to require seller or admin role"""
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role, is_approved FROM users WHERE user_id = %s", (current_user_id,))
        user = cursor.fetchone()
        cursor.close()
        
        if not user or (user[0] not in ['seller', 'admin']) or (user[0] == 'seller' and not user[1]):
            return jsonify({"error": "Seller access required and account must be approved"}), 403
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def login_required(fn):
    """Decorator to require any authenticated user"""
    @jwt_required()
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

# --- Authentication Routes ---

@app.route('/api/auth/register', methods=['POST'])
def register():
    """
    User Registration
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
            - firstName
            - lastName
          properties:
            email:
              type: string
            password:
              type: string
            firstName:
              type: string
            lastName:
              type: string
    responses:
      201:
        description: User registered successfully
      400:
        description: Missing required fields or email already exists
    """
    try:
        data = request.get_json()
        
        if not data or not all(k in data for k in ['email', 'password', 'firstName', 'lastName']):
            return jsonify({"error": "Missing required fields"}), 400
        
        email = data['email']
        password = data['password']
        first_name = data['firstName']
        last_name = data['lastName']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if email already exists
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            return jsonify({"error": "Email already registered"}), 400
        
        # Hash password and create user
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        cursor.execute("""
            INSERT INTO users (email, password_hash, first_name, last_name, role, is_approved)
            VALUES (%s, %s, %s, %s, 'user', TRUE)
            RETURNING user_id, email, first_name, last_name, role
        """, (email, password_hash, first_name, last_name))
        
        user = cursor.fetchone()
        conn.commit()
        cursor.close()
        
        # Create access token
        access_token = create_access_token(identity=user[0])
        
        return jsonify({
            "message": "User registered successfully",
            "user": {
                "user_id": user[0],
                "email": user[1],
                "first_name": user[2],
                "last_name": user[3],
                "role": user[4]
            },
            "access_token": access_token
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    User Login
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
    try:
        data = request.get_json()
        
        if not data or not all(k in data for k in ['email', 'password']):
            return jsonify({"error": "Missing email or password"}), 400
        
        email = data['email']
        password = data['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, email, password_hash, first_name, last_name, role, is_approved 
            FROM users 
            WHERE email = %s
        """, (email,))
        
        user = cursor.fetchone()
        cursor.close()
        
        if not user or not bcrypt.check_password_hash(user[2], password):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Check if user is approved (for sellers)
        if user[5] == 'seller' and not user[6]:
            return jsonify({"error": "Seller account pending approval"}), 403
        
        # Create access token
        access_token = create_access_token(identity=user[0])
        
        return jsonify({
            "message": "Login successful",
            "user": {
                "user_id": user[0],
                "email": user[1],
                "first_name": user[3],
                "last_name": user[4],
                "role": user[5],
                "is_approved": user[6]
            },
            "access_token": access_token
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """
    Get Current User
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: User data retrieved successfully
      404:
        description: User not found
    """
    try:
        current_user_id = get_jwt_identity()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, email, first_name, last_name, role, is_approved, created_at
            FROM users 
            WHERE user_id = %s
        """, (current_user_id,))
        
        user = cursor.fetchone()
        cursor.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "user": {
                "user_id": user[0],
                "email": user[1],
                "first_name": user[2],
                "last_name": user[3],
                "role": user[4],
                "is_approved": user[5],
                "created_at": user[6].isoformat() if user[6] else None
            }
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Health check endpoint
@app.route('/health')
def health_check():
    """
    Health Check
    ---
    tags:
      - System
    responses:
      200:
        description: System health status
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        return jsonify({
            "status": "healthy", 
            "database": "connected",
            "db_host": os.environ.get('DB_HOST', 'Not set')
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy", 
            "database": "disconnected", 
            "error": str(e)
        }), 500
# Debug endpoint to check environment variables
@app.route('/api/debug/env')
def debug_env():
    """Debug endpoint to check environment variables"""
    return jsonify({
        "db_host_set": bool(os.environ.get('DB_HOST')),
        "db_name_set": bool(os.environ.get('DB_NAME')),
        "db_user_set": bool(os.environ.get('DB_USER')),
        "db_pass_set": bool(os.environ.get('DB_PASS')),
        "jwt_secret_set": bool(os.environ.get('JWT_SECRET_KEY')),
        "db_host_value": os.environ.get('DB_HOST', 'Not set')[:10] + "..." if os.environ.get('DB_HOST') else 'Not set',
        "db_name_value": os.environ.get('DB_NAME', 'Not set'),
        "db_user_value": os.environ.get('DB_USER', 'Not set'),
        "jwt_secret_value": os.environ.get('JWT_SECRET_KEY', 'Not set')[:10] + "..." if os.environ.get('JWT_SECRET_KEY') else 'Not set'
    })

# --- Frontend Routes ---
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/admin')
def serve_admin():
    return send_from_directory('.', 'admin.html')

@app.route('/api-docs')
def serve_api_docs():
    return send_from_directory('.', 'api-docs.html')

@app.route('/swagger')
@jwt_required()
def serve_swagger():
    """Serve Swagger UI only to authenticated users"""
    current_user_id = get_jwt_identity()
    
    # Check if user is admin or approved seller
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role, is_approved FROM users WHERE user_id = %s", (current_user_id,))
    user = cursor.fetchone()
    cursor.close()
    
    if not user or (user[0] not in ['admin', 'seller']) or (user[0] == 'seller' and not user[1]):
        return jsonify({"error": "Access denied. Admin or approved seller required."}), 403
    
    return send_from_directory('.', 'swagger.html')

# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# --- Image Upload Endpoint ---
@app.route('/api/admin/upload', methods=['POST'])
@jwt_required()
def upload_image():
    """
    Upload Image
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    parameters:
      - in: formData
        name: image
        type: file
        required: true
        description: Image file to upload
    responses:
      200:
        description: Image uploaded successfully
      400:
        description: No file or invalid file type
    """
    try:
        current_user_id = get_jwt_identity()
        
        # Check if user is seller or admin
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role, is_approved FROM users WHERE user_id = %s", (current_user_id,))
        user = cursor.fetchone()
        cursor.close()
        
        if not user or (user[0] not in ['seller', 'admin']) or (user[0] == 'seller' and not user[1]):
            return jsonify({"error": "Seller access required and account must be approved"}), 403
        
        # Check if the post request has the file part
        if 'image' not in request.files:
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['image']
        
        # If user does not select file, browser also submits an empty part without filename
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        
        if file and allowed_file(file.filename):
            # Generate unique filename to prevent overwriting
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            
            # Ensure upload folder exists
            ensure_upload_folder()
            
            # Save file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Return the URL path for the saved image
            image_url = f"/static/uploads/{unique_filename}"
            return jsonify({
                "message": "Image uploaded successfully",
                "image_url": image_url
            }), 200
        else:
            return jsonify({"error": "File type not allowed. Please upload PNG, JPG, JPEG, GIF, or WEBP."}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- API Endpoints ---
@app.route('/api/products', methods=['GET'])
def get_products():
    """
    Get Products
    ---
    tags:
      - Products
    parameters:
      - in: query
        name: search
        type: string
        required: false
        description: Search term for product name or description
      - in: query
        name: admin
        type: boolean
        required: false
        description: Include admin-only data (requires authentication)
    responses:
      200:
        description: List of products
    """
    try:
        search_term = request.args.get('search', '') 
        admin_mode = request.args.get('admin', 'false').lower() == 'true'
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        query = """
            SELECT
                p.product_id, p.name, p.description, p.price, p.category, 
                p.image_url, i.quantity,
                CASE
                    WHEN i.quantity = 0 THEN 'Out of Stock'
                    WHEN i.quantity < 10 THEN 'Low Stock'
                    ELSE 'In Stock'
                END AS stock_status
            FROM products p
            JOIN inventory i ON p.product_id = i.product_id
            WHERE 1=1
        """
        
        params = []
        if search_term:
            query += " AND (p.name ILIKE %s OR p.description ILIKE %s)"
            params.extend([f'%{search_term}%', f'%{search_term}%'])
        
        cursor.execute(query, params)
        products = cursor.fetchall()
        cursor.close()
        
        # If not in admin mode, remove quantity field for security
        if not admin_mode:
            for product in products:
                if 'quantity' in product:
                    del product['quantity']
        
        return jsonify(products)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/products/<int:product_id>/related', methods=['GET'])
def get_related_products(product_id):
    """
    Get Related Products
    ---
    tags:
      - Products
    parameters:
      - in: path
        name: product_id
        type: integer
        required: true
        description: Product ID
    responses:
      200:
        description: List of related products
      404:
        description: Product not found
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT category FROM products WHERE product_id = %s", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            return jsonify({"error": "Product not found"}), 404

        current_category = product['category']
        
        cursor.execute("""
            SELECT product_id, name, price, category, image_url 
            FROM products 
            WHERE category = %s AND product_id != %s LIMIT 3
        """, (current_category, product_id))
        related = cursor.fetchall()
        
        cursor.close()
        return jsonify(related)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Admin API Endpoints ---

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_users():
    """
    Get All Users (Admin Only)
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    responses:
      200:
        description: List of users
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT user_id, email, first_name, last_name, role, is_approved, created_at
            FROM users 
            ORDER BY created_at DESC
        """)
        
        users = cursor.fetchall()
        cursor.close()
        
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """
    Update User (Admin Only)
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    parameters:
      - in: path
        name: user_id
        type: integer
        required: true
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            role:
              type: string
            is_approved:
              type: boolean
    responses:
      200:
        description: User updated successfully
      404:
        description: User not found
    """
    try:
        data = request.get_json()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            return jsonify({"error": "User not found"}), 404
        
        # Update user
        update_fields = []
        params = []
        
        if 'role' in data:
            update_fields.append("role = %s")
            params.append(data['role'])
        
        if 'is_approved' in data:
            update_fields.append("is_approved = %s")
            params.append(data['is_approved'])
        
        if update_fields:
            update_fields.append("updated_at = CURRENT_TIMESTAMP")
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE user_id = %s"
            params.append(user_id)
            
            cursor.execute(query, params)
            conn.commit()
        
        cursor.close()
        return jsonify({"message": "User updated successfully"}), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/products', methods=['POST'])
@jwt_required()
def create_product():
    """
    Create Product (Seller/Admin Only)
    ---
    tags:
      - Products
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
            - price
            - category
            - quantity
          properties:
            name:
              type: string
            description:
              type: string
            price:
              type: number
            category:
              type: string
            image_url:
              type: string
            quantity:
              type: integer
    responses:
      201:
        description: Product created successfully
      400:
        description: Missing required fields
    """
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data or not all(k in data for k in ['name', 'price', 'category', 'quantity']):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Check if user is seller or admin
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role, is_approved FROM users WHERE user_id = %s", (current_user_id,))
        user = cursor.fetchone()
        
        if not user or (user[0] not in ['seller', 'admin']) or (user[0] == 'seller' and not user[1]):
            cursor.close()
            return jsonify({"error": "Seller access required and account must be approved"}), 403
        
        # Use default image if none provided
        image_url = data.get('image_url', '/static/default.png')
        
        # Insert product
        cursor.execute("""
            INSERT INTO products (name, description, price, category, image_url, created_by)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING product_id
        """, (data['name'], data.get('description', ''), data['price'], 
              data['category'], image_url, current_user_id))
        
        product_id = cursor.fetchone()[0]
        
        # Insert inventory
        cursor.execute("""
            INSERT INTO inventory (product_id, quantity)
            VALUES (%s, %s)
        """, (product_id, data['quantity']))
        
        conn.commit()
        cursor.close()
        
        return jsonify({"message": "Product created successfully", "product_id": product_id}), 201
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    """
    Update Product (Seller/Admin Only)
    ---
    tags:
      - Products
    security:
      - Bearer: []
    parameters:
      - in: path
        name: product_id
        type: integer
        required: true
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
            price:
              type: number
            category:
              type: string
            image_url:
              type: string
            quantity:
              type: integer
    responses:
      200:
        description: Product updated successfully
      404:
        description: Product not found
    """
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if product exists and user has permission
        cursor.execute("SELECT created_by FROM products WHERE product_id = %s", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        # Check if user is admin or the product owner
        cursor.execute("SELECT role FROM users WHERE user_id = %s", (current_user_id,))
        user = cursor.fetchone()
        
        if not user or (user[0] != 'admin' and product[0] != current_user_id):
            return jsonify({"error": "Permission denied"}), 403
        
        # Update product
        cursor.execute("""
            UPDATE products 
            SET name = %s, description = %s, price = %s, category = %s, image_url = %s, updated_at = CURRENT_TIMESTAMP
            WHERE product_id = %s
        """, (data['name'], data.get('description', ''), data['price'], 
              data['category'], data.get('image_url', '/static/default.png'), product_id))
        
        # Update inventory
        cursor.execute("""
            UPDATE inventory SET quantity = %s WHERE product_id = %s
        """, (data['quantity'], product_id))
        
        conn.commit()
        cursor.close()
        
        return jsonify({"message": "Product updated successfully"}), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    """
    Delete Product (Seller/Admin Only)
    ---
    tags:
      - Products
    security:
      - Bearer: []
    parameters:
      - in: path
        name: product_id
        type: integer
        required: true
    responses:
      200:
        description: Product deleted successfully
      404:
        description: Product not found
    """
    try:
        current_user_id = get_jwt_identity()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if product exists and user has permission
        cursor.execute("SELECT created_by FROM products WHERE product_id = %s", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        # Check if user is admin or the product owner
        cursor.execute("SELECT role FROM users WHERE user_id = %s", (current_user_id,))
        user = cursor.fetchone()
        
        if not user or (user[0] != 'admin' and product[0] != current_user_id):
            return jsonify({"error": "Permission denied"}), 403
        
        # Delete from inventory first (foreign key constraint)
        cursor.execute("DELETE FROM inventory WHERE product_id = %s", (product_id,))
        
        # Delete product
        cursor.execute("DELETE FROM products WHERE product_id = %s", (product_id,))
        
        conn.commit()
        cursor.close()
        
        return jsonify({"message": "Product deleted successfully"}), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

# --- Run the App ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    print(f"🚀 Starting CircuitCart Flask app on port {port}")
    app.run(debug=False, host='0.0.0.0', port=port)