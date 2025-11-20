import os
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, g, send_from_directory, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import time
import uuid
from werkzeug.utils import secure_filename
from flasgger import Swagger
import base64

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# --- Swagger Configuration ---
app.config['SWAGGER'] = {
    'title': 'CircuitCart API',
    'uiversion': 3,
    'doc_expansion': 'list',
    'url_prefix': '/swagger',
    'securityDefinitions': {
        'cookieAuth': {
            'type': 'apiKey',
            'in': 'cookie',
            'name': 'session'
        }
    }
}
swagger = Swagger(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'serve_index'

# --- Secure Swagger UI ---
@app.before_request
def protect_swagger_ui():
    if request.path.startswith(app.config['SWAGGER']['url_prefix']):
        if not current_user.is_authenticated:
            return redirect(url_for('serve_index'))
        if not current_user.is_admin():
            return jsonify({"error": "Admin access required"}), 403

# Image upload configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- User Class ---
class User(UserMixin):
    def __init__(self, user_id, username, email, role, approved, suspended):
        self.id = user_id
        self.username = username
        self.email = email
        self.role = role
        self.approved = approved
        self.suspended = suspended

    @property
    def is_active(self):
        return self.approved and not self.suspended

    def is_admin(self):
        return self.role == 'admin' and self.is_active

    def is_seller(self):
        return self.role == 'seller' and self.is_active

    def is_user(self):
        return self.role == 'user' and self.is_active

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        if user_data:
            return User(
                user_id=user_data['user_id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                approved=user_data['approved'],
                suspended=user_data['suspended']
            )
        return None
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

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


@app.route('/healthz')
def healthz_check():
    """Simple health check for load balancer"""
    return "healthy", 200

@app.teardown_appcontext
def close_connection(exception):
    """Closes the DB connection at the end of the request."""
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        db_conn.close()

def init_database():
    """Initializes the database with tables and sample data."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Create 'users' table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            approved BOOLEAN DEFAULT FALSE,
            suspended BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Create 'products' table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            product_id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            category TEXT,
            image_url TEXT,
            created_by INTEGER REFERENCES users(user_id) ON DELETE SET NULL
        )
        ''')

        # Create 'inventory' table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            product_id INTEGER PRIMARY KEY,
            quantity INTEGER NOT NULL,
            FOREIGN KEY (product_id) REFERENCES products (product_id) ON DELETE CASCADE
        )
        ''')

        # Create 'api_keys' table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
            api_key TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Check if users table is empty and create admin user
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        if user_count == 0:
            print("👤 Creating admin user...")
            admin_password_hash = generate_password_hash('admin')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, approved, suspended)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, ('admin', 'admin@shop.com', admin_password_hash, 'admin', True, False))

            # Create sample seller and user
            seller_password_hash = generate_password_hash('seller123')
            user_password_hash = generate_password_hash('user123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, approved, suspended)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, ('seller1', 'seller@shop.com', seller_password_hash, 'seller', True, False))
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, approved, suspended)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, ('user1', 'user@shop.com', user_password_hash, 'user', True, False))

            # Check if products table is empty
            cursor.execute("SELECT COUNT(*) FROM products")
            count = cursor.fetchone()[0]
            if count == 0:
                print("📦 Inserting sample products...")
                products_data = [
                    ('Pro Laptop', 'A 16-inch high-performance laptop for professionals.', 1200.00, 'Electronics', '/static/p1.png', 1),
                    ('Classic Coffee Mug', 'A sturdy 12oz ceramic mug, dishwasher safe.', 15.50, 'Homeware', '/static/p2.png', 1),
                    ('Wireless Mouse', 'Ergonomic mouse with 8-button layout and 2-year battery life.', 75.00, 'Electronics', '/static/p3.png', 1),
                    ('Cotton T-Shirt', '100% premium soft cotton. Pre-shrunk and tagless.', 20.00, 'Apparel', '/static/p4.png', 1),
                    ('Running Shoes', 'Lightweight and breathable. Perfect for road running.', 89.99, 'Apparel', '/static/p5.png', 1)
                ]
                cursor.executemany("""
                    INSERT INTO products (name, description, price, category, image_url, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, products_data)

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
        cursor.close()
    except Exception as e:
        conn.rollback()
        print(f"❌ Database initialization failed: {e}")

# Initialize database when app starts
with app.app_context():
    try:
        init_database()
    except Exception as e:
        print(f"❌ Initial setup failed: {e}")

# --- API Key Validation Functions ---
def validate_api_key(api_key):
    """Validate API key and return user info"""
    if not api_key:
        return None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT u.user_id, u.username, u.email, u.role, u.approved, u.suspended
            FROM api_keys k
            JOIN users u ON k.user_id = u.user_id
            WHERE k.api_key = %s AND u.approved = TRUE AND u.suspended = FALSE
        """, (api_key,))
        user_data = cursor.fetchone()
        cursor.close()
        if user_data:
            return {
                'user_id': user_data['user_id'],
                'username': user_data['username'],
                'email': user_data['email'],
                'role': user_data['role'],
                'approved': user_data['approved'],
                'suspended': user_data['suspended']
            }
        return None
    except Exception as e:
        print(f"API key validation error: {e}")
        return None

# --- API Authentication Decorators ---
from functools import wraps

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        user_info = validate_api_key(api_key)
        if not user_info:
            return jsonify({"error": "Invalid or expired API key"}), 401
        g.api_user = user_info
        return f(*args, **kwargs)
    return decorated_function

def admin_api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        user_info = validate_api_key(api_key)
        if not user_info:
            return jsonify({"error": "Invalid or expired API key"}), 401
        if user_info['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        g.api_user = user_info
        return f(*args, **kwargs)
    return decorated_function

def seller_api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        user_info = validate_api_key(api_key)
        if not user_info:
            return jsonify({"error": "Invalid or expired API key"}), 401
        if user_info['role'] not in ['admin', 'seller']:
            return jsonify({"error": "Seller or Admin access required"}), 403
        g.api_user = user_info
        return f(*args, **kwargs)
    return decorated_function

# --- Health Check ---
@app.route('/health')
def health_check():
    """
    Health Check
    Checks the status of the application and database.
    ---
    tags:
      - General
    responses:
      200:
        description: Application is healthy.
      500:
        description: Application or database is unhealthy.
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

# --- Frontend Routes ---
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/admin/users')
@login_required
def serve_admin_users():
    if not current_user.is_admin():
        return jsonify({"error": "Admin access required"}), 403
    return send_from_directory('.', 'admin-users.html')

@app.route('/admin/products')
@login_required
def serve_admin_products():
    if not (current_user.is_admin() or current_user.is_seller()):
        return jsonify({"error": "Admin or Seller access required"}), 403
    return send_from_directory('.', 'admin-products.html')

@app.route('/admin/keys')
@login_required
def serve_admin_keys():
    if not current_user.is_admin():
        return jsonify({"error": "Admin access required"}), 403
    return send_from_directory('.', 'admin-keys.html')

@app.route('/swagger')
@login_required
def redirect_to_swagger_ui():
    """
    Redirect to Swagger UI
    Redirects the base /swagger URL to the actual UI page.
    ---
    tags:
      - General
    security:
      - cookieAuth: []
    responses:
      302:
        description: Redirects to the /swagger/apidocs/ page.
      403:
        description: Admin access required (handled by before_request).
    """
    return redirect('/swagger/apidocs/')

# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# --- Authentication Endpoints ---
@app.route('/api/register', methods=['POST'])
def register():
    """
    Register a new user
    Creates a new user account. Seller accounts require approval.
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            username:
              type: string
            email:
              type: string
            password:
              type: string
            role:
              type: string
              enum: ['user', 'seller']
    responses:
      201:
        description: User registered successfully.
      400:
        description: Missing fields or user already exists.
    """
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ['username', 'email', 'password']):
            return jsonify({"error": "Missing required fields"}), 400

        username = data['username']
        email = data['email']
        password = data['password']
        role = data.get('role', 'user')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            cursor.close()
            return jsonify({"error": "Username or email already exists"}), 400

        password_hash = generate_password_hash(password)
        approved = False
        if role == 'user':
            approved = True

        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, approved, suspended)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING user_id
        """, (username, email, password_hash, role, approved, False))
        user_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()

        return jsonify({
            "message": "User registered successfully",
            "user_id": user_id,
            "needs_approval": not approved
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """
    Log in
    Logs in a user and creates a session cookie.
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful.
      401:
        description: Invalid username or password.
      403:
        description: Account pending approval or suspended.
    """
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ['username', 'password']):
            return jsonify({"error": "Missing username or password"}), 400

        username = data['username']
        password = data['password']

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()

        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(
                user_id=user_data['user_id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                approved=user_data['approved'],
                suspended=user_data['suspended']
            )

            if not user.is_active:
                error_msg = "Account pending approval"
                if user.suspended:
                    error_msg = "Account has been suspended"
                elif not user.approved:
                    error_msg = "Account pending approval"
                return jsonify({"error": error_msg}), 403

            login_user(user)
            return jsonify({
                "message": "Login successful",
                "user": {
                    "user_id": user_data['user_id'],
                    "username": user_data['username'],
                    "email": user_data['email'],
                    "role": user_data['role']
                }
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """
    Log out
    Clears the user's session.
    ---
    tags:
      - Authentication
    security:
      - cookieAuth: []
    responses:
      200:
        description: Logout successful.
    """
    logout_user()
    return jsonify({"message": "Logout successful"}), 200

@app.route('/api/user')
@login_required
def get_current_user():
    """
    Get Current User
    Returns the details of the currently logged-in user.
    ---
    tags:
      - Authentication
    security:
      - cookieAuth: []
    responses:
      200:
        description: User details.
    """
    return jsonify({
        "user_id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role
    }), 200

# --- User API Key Management ---
@app.route('/api/user/keys', methods=['GET'])
@login_required
def get_user_api_keys():
    """
    Get Current User's API Keys
    Returns the API keys for the currently logged-in user.
    ---
    tags:
      - Authentication
    security:
      - cookieAuth: []
    responses:
      200:
        description: List of user's API keys.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT key_id, api_key, created_at
            FROM api_keys
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (current_user.id,))
        keys = cursor.fetchall()
        cursor.close()
        return jsonify(keys)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/user/keys', methods=['POST'])
@login_required
def create_user_api_key():
    """
    Create API Key for Current User
    Creates a new API key for the currently logged-in user.
    ---
    tags:
      - Authentication
    security:
      - cookieAuth: []
    responses:
      201:
        description: API key created successfully.
    """
    try:
        new_key = f"sk_{uuid.uuid4().hex}"
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO api_keys (user_id, api_key) VALUES (%s, %s)",
            (current_user.id, new_key)
        )
        conn.commit()
        cursor.close()
        return jsonify({
            "message": "API key created successfully",
            "api_key": new_key
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

# --- User Management Endpoints (Admin only) ---
@app.route('/api/admin/users', methods=['GET'])
@api_key_required
@admin_api_key_required
def get_users():
    """
    Get All Users (Admin)
    Retrieves a list of all users in the system.
    ---
    tags:
      - User Management
    parameters:
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      200:
        description: A list of users.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT user_id, username, email, role, approved, suspended, created_at
            FROM users ORDER BY created_at DESC
        """)
        users = cursor.fetchall()
        cursor.close()
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<int:user_id>/approve', methods=['POST'])
@api_key_required
@admin_api_key_required
def approve_user(user_id):
    """
    Approve User (Admin)
    Approves a pending user account (e.g., a seller).
    ---
    tags:
      - User Management
    parameters:
      - in: path
        name: user_id
        type: integer
        required: true
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      200:
        description: User approved successfully.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET approved = TRUE WHERE user_id = %s", (user_id,))
        conn.commit()
        cursor.close()
        return jsonify({"message": "User approved successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@api_key_required
@admin_api_key_required
def update_user_role(user_id):
    """
    Update User Role (Admin)
    Changes the role of a user (user, seller, admin).
    ---
    tags:
      - User Management
    parameters:
      - in: path
        name: user_id
        type: integer
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            role:
              type: string
              enum: ['user', 'seller', 'admin']
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      200:
        description: User role updated successfully.
      400:
        description: Invalid role.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    try:
        data = request.get_json()
        new_role = data.get('role')
        if new_role not in ['user', 'seller', 'admin']:
            return jsonify({"error": "Invalid role"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = %s WHERE user_id = %s", (new_role, user_id))
        conn.commit()
        cursor.close()
        return jsonify({"message": "User role updated successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<int:user_id>/suspend', methods=['POST'])
@api_key_required
@admin_api_key_required
def suspend_user(user_id):
    """
    Suspend User (Admin)
    Suspends a user's account, preventing login.
    ---
    tags:
      - User Management
    parameters:
      - in: path
        name: user_id
        type: integer
        required: true
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      200:
        description: User suspended successfully.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET suspended = TRUE WHERE user_id = %s", (user_id,))
        conn.commit()
        cursor.close()
        return jsonify({"message": "User suspended successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<int:user_id>/activate', methods=['POST'])
@api_key_required
@admin_api_key_required
def activate_user(user_id):
    """
    Activate User (Admin)
    Activates (un-suspends) a user's account.
    ---
    tags:
      - User Management
    parameters:
      - in: path
        name: user_id
        type: integer
        required: true
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      200:
        description: User activated successfully.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET suspended = FALSE WHERE user_id = %s", (user_id,))
        conn.commit()
        cursor.close()
        return jsonify({"message": "User activated successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@api_key_required
@admin_api_key_required
def delete_user(user_id):
    """
    Delete User (Admin)
    Permanently deletes a user account.
    ---
    tags:
      - User Management
    parameters:
      - in: path
        name: user_id
        type: integer
        required: true
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      200:
        description: User deleted successfully.
      400:
        description: Cannot delete your own account.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    if user_id == g.api_user['user_id']:
        return jsonify({"error": "Cannot delete your own account"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()
        cursor.close()
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

# --- API Key Management Endpoints (Admin only) ---
@app.route('/api/admin/keys', methods=['GET'])
@api_key_required
@admin_api_key_required
def get_api_keys():
    """
    Get All API Keys (Admin)
    Retrieves a list of all API keys.
    ---
    tags:
      - User Management
    parameters:
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      200:
        description: A list of API keys.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT k.key_id, k.api_key, k.created_at, u.username
            FROM api_keys k
            JOIN users u ON k.user_id = u.user_id
            ORDER BY k.created_at DESC
        """)
        keys = cursor.fetchall()
        cursor.close()
        return jsonify(keys)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/keys', methods=['POST'])
@api_key_required
@admin_api_key_required
def create_api_key():
    """
    Create API Key (Admin)
    Creates a new API key for a specified user.
    ---
    tags:
      - User Management
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            user_id:
              type: integer
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      201:
        description: API key created successfully.
      400:
        description: User ID is required.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({"error": "User ID is required"}), 400

        new_key = f"sk_{uuid.uuid4().hex}"
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO api_keys (user_id, api_key) VALUES (%s, %s)",
            (user_id, new_key)
        )
        conn.commit()
        cursor.close()
        return jsonify({
            "message": "API key created successfully",
            "api_key": new_key
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/keys/<int:key_id>', methods=['DELETE'])
@api_key_required
@admin_api_key_required
def delete_api_key(key_id):
    """
    Delete API Key (Admin)
    Permanently deletes an API key.
    ---
    tags:
      - User Management
    parameters:
      - in: path
        name: key_id
        type: integer
        required: true
      - in: header
        name: X-API-Key
        type: string
        required: true
    responses:
      200:
        description: API key deleted successfully.
      401:
        description: API key required.
      403:
        description: Admin access required.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM api_keys WHERE key_id = %s", (key_id,))
        conn.commit()
        cursor.close()
        return jsonify({"message": "API key deleted successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

# --- Image Upload Endpoint (Local Storage with Base64) ---
@app.route('/api/admin/upload', methods=['POST'])
@api_key_required
@seller_api_key_required
def upload_image():
    """
    Upload Image (Admin/Seller)
    Uploads a product image using base64 encoding.
    ---
    tags:
      - Product Management
    parameters:
      - in: header
        name: X-API-Key
        type: string
        required: true
      - in: formData
        name: image
        type: file
        required: true
        description: The image file to upload.
    responses:
      200:
        description: Image uploaded successfully.
      400:
        description: No file part or file type not allowed.
      401:
        description: API key required.
      403:
        description: Access denied.
    """
    try:
        print("📸 Local image upload started")
        
        if 'image' not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files['image']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        print(f"📁 File received: {file.filename}")
        
        if file and allowed_file(file.filename):
            # Read file data
            file_data = file.read()
            
            # Convert to base64
            encoded_string = base64.b64encode(file_data).decode('utf-8')
            
            # Determine MIME type
            mime_type = file.content_type
            if not mime_type:
                # Fallback based on file extension
                ext = file.filename.rsplit('.', 1)[1].lower()
                mime_type = f"image/{ext}" if ext in ['png', 'jpg', 'jpeg', 'gif', 'webp'] else 'image/jpeg'
            
            # Create data URL
            image_url = f"data:{mime_type};base64,{encoded_string}"
            
            print(f"✅ File converted to base64, size: {len(encoded_string)} chars")
            
            return jsonify({
                "message": "Image uploaded as base64",
                "image_url": image_url,
                "note": "Base64 encoding - works in all environments"
            }), 200
            
        else:
            return jsonify({"error": "File type not allowed. Please upload PNG, JPG, JPEG, GIF, or WEBP."}), 400

    except Exception as e:
        print(f"💥 Base64 upload failed: {str(e)}")
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

# --- API Endpoints ---
@app.route('/api/products', methods=['GET'])
def get_products():
    """
    Get All Products
    Retrieves all products, with optional search.
    ---
    tags:
      - Products
    parameters:
      - in: query
        name: search
        type: string
        description: Filter products by name or description.
      - in: query
        name: admin
        type: boolean
        description: If true, returns stock quantity (requires API key).
      - in: header
        name: X-API-Key
        type: string
        required: false
        description: API key for admin mode access
    responses:
      200:
        description: A list of products.
      401:
        description: API key required for admin mode.
    """
    try:
        search_term = request.args.get('search', '')
        admin_mode = request.args.get('admin', 'false').lower() == 'true'

        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        user_info = validate_api_key(api_key) if api_key else None

        if admin_mode and not user_info:
            return jsonify({"error": "API key required for admin mode"}), 401

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
        """
        params = []
        if search_term:
            query += " WHERE p.name ILIKE %s OR p.description ILIKE %s"
            params.extend([f'%{search_term}%', f'%{search_term}%'])

        cursor.execute(query, params)
        products = cursor.fetchall()
        cursor.close()

        if not admin_mode or not user_info:
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
    Retrieves 3 related products from the same category.
    ---
    tags:
      - Products
    parameters:
      - in: path
        name: product_id
        type: integer
        required: true
    responses:
      200:
        description: A list of related products.
      404:
        description: Product not found.
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

# --- Product Management API Endpoints (Admin / Seller) ---
@app.route('/api/admin/products', methods=['POST'])
@api_key_required
@seller_api_key_required
def create_product():
    """
    Create Product (Admin/Seller)
    Adds a new product to the database.
    ---
    tags:
      - Product Management
    parameters:
      - in: header
        name: X-API-Key
        type: string
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            name: { type: string }
            description: { type: string }
            price: { type: number }
            category: { type: string }
            quantity: { type: integer }
            image_url: { type: string }
    responses:
      201:
        description: Product created successfully.
      400:
        description: Missing required fields.
      401:
        description: API key required.
      403:
        description: Access denied.
    """
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ['name', 'price', 'category', 'quantity']):
            return jsonify({"error": "Missing required fields"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        image_url = data.get('image_url', '/static/default.png')
        cursor.execute("""
            INSERT INTO products (name, description, price, category, image_url, created_by)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING product_id
        """, (data['name'], data.get('description', ''), data['price'],
              data['category'], image_url, g.api_user['user_id']))
        product_id = cursor.fetchone()[0]
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
@api_key_required
@seller_api_key_required
def update_product(product_id):
    """
    Update Product (Admin/Seller)
    Updates an existing product.
    ---
    tags:
      - Product Management
    parameters:
      - in: header
        name: X-API-Key
        type: string
        required: true
      - in: path
        name: product_id
        type: integer
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            name: { type: string }
            description: { type: string }
            price: { type: number }
            category: { type: string }
            quantity: { type: integer }
            image_url: { type: string }
    responses:
      200:
        description: Product updated successfully.
      401:
        description: API key required.
      403:
        description: Access denied.
      404:
        description: Product not found.
    """
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM products WHERE product_id = %s", (product_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Product not found"}), 404

        cursor.execute("""
            UPDATE products
            SET name = %s, description = %s, price = %s, category = %s, image_url = %s
            WHERE product_id = %s
        """, (data['name'], data.get('description', ''), data['price'],
              data['category'], data.get('image_url', '/static/default.png'), product_id))
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
@api_key_required
@admin_api_key_required
def delete_product(product_id):
    """
    Delete Product (Admin)
    Permanently deletes a product.
    ---
    tags:
      - Product Management
    parameters:
      - in: header
        name: X-API-Key
        type: string
        required: true
      - in: path
        name: product_id
        type: integer
        required: true
    responses:
      200:
        description: Product deleted successfully.
      401:
        description: API key required.
      403:
        description: Admin access required.
      404:
        description: Product not found.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM products WHERE product_id = %s", (product_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Product not found"}), 404

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
    print(f"🚀 Starting Flask app on port {port}")
    app.run(debug=False, host='0.0.0.0', port=port)