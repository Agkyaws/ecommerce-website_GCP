import os
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, g, send_from_directory, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import time
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'serve_index'

# Image upload configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_upload_folder():
    """Ensure the upload folder exists"""
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, email, role, approved):
        self.id = user_id
        self.username = username
        self.email = email
        self.role = role
        self.approved = approved

    def is_admin(self):
        return self.role == 'admin' and self.approved
    
    def is_seller(self):
        return self.role == 'seller' and self.approved
    
    def is_user(self):
        return self.role == 'user' and self.approved

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
                approved=user_data['approved']
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
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            approved BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            created_by INTEGER REFERENCES users(user_id)
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

        # Check if users table is empty and create admin user
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        if user_count == 0:
            print("👤 Creating admin user...")
            admin_password_hash = generate_password_hash('admin123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, approved) 
                VALUES (%s, %s, %s, %s, %s)
            """, ('admin', 'admin@shop.com', admin_password_hash, 'admin', True))
            
            # Create sample seller and user
            seller_password_hash = generate_password_hash('seller123')
            user_password_hash = generate_password_hash('user123')
            
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, approved) 
                VALUES (%s, %s, %s, %s, %s)
            """, ('seller1', 'seller@shop.com', seller_password_hash, 'seller', True))
            
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, approved) 
                VALUES (%s, %s, %s, %s, %s)
            """, ('user1', 'user@shop.com', user_password_hash, 'user', True))

        # Check if products table is empty
        cursor.execute("SELECT COUNT(*) FROM products")
        count = cursor.fetchone()[0]
        
        if count == 0:
            print("📦 Inserting sample products...")
            # Sample products
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

# Health check endpoint
@app.route('/health')
def health_check():
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

@app.route('/admin')
@login_required
def serve_admin():
    if not current_user.is_admin():
        return redirect(url_for('serve_index'))
    return send_from_directory('.', 'admin.html')

@app.route('/api-docs')
@login_required
def serve_api_docs():
    if not current_user.is_admin():
        return redirect(url_for('serve_index'))
    return send_from_directory('.', 'api-docs.html')

# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# --- Authentication Endpoints ---
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data or not all(k in data for k in ['username', 'email', 'password']):
            return jsonify({"error": "Missing required fields"}), 400
        
        username = data['username']
        email = data['email']
        password = data['password']
        role = data.get('role', 'user')  # Default role is 'user'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            cursor.close()
            return jsonify({"error": "Username or email already exists"}), 400
        
        # Hash password and create user
        password_hash = generate_password_hash(password)
        
        # New users (except admin) need approval
        approved = False
        if role == 'user':
            approved = True  # Regular users are auto-approved
        
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, approved) 
            VALUES (%s, %s, %s, %s, %s) RETURNING user_id
        """, (username, email, password_hash, role, approved))
        
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
            if not user_data['approved']:
                return jsonify({"error": "Account pending approval"}), 403
                
            user = User(
                user_id=user_data['user_id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                approved=user_data['approved']
            )
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
    logout_user()
    return jsonify({"message": "Logout successful"}), 200

@app.route('/api/user')
@login_required
def get_current_user():
    return jsonify({
        "user_id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role
    }), 200

# --- User Management Endpoints (Admin only) ---
@app.route('/api/admin/users', methods=['GET'])
@login_required
def get_users():
    if not current_user.is_admin():
        return jsonify({"error": "Admin access required"}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT user_id, username, email, role, approved, created_at 
            FROM users ORDER BY created_at DESC
        """)
        users = cursor.fetchall()
        cursor.close()
        
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<int:user_id>/approve', methods=['POST'])
@login_required
def approve_user(user_id):
    if not current_user.is_admin():
        return jsonify({"error": "Admin access required"}), 403
    
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
@login_required
def update_user_role(user_id):
    if not current_user.is_admin():
        return jsonify({"error": "Admin access required"}), 403
    
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

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        return jsonify({"error": "Admin access required"}), 403
    
    try:
        # Prevent admin from deleting themselves
        if user_id == current_user.id:
            return jsonify({"error": "Cannot delete your own account"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            return jsonify({"error": "User not found"}), 404
        
        # Check if user has created any products
        cursor.execute("SELECT COUNT(*) FROM products WHERE created_by = %s", (user_id,))
        product_count = cursor.fetchone()[0]
        
        if product_count > 0:
            # Delete user's products and inventory
            cursor.execute("DELETE FROM inventory WHERE product_id IN (SELECT product_id FROM products WHERE created_by = %s)", (user_id,))
            cursor.execute("DELETE FROM products WHERE created_by = %s", (user_id,))
        
        # Delete the user
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()
        cursor.close()
        
        return jsonify({"message": "User deleted successfully"}), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

# --- Image Upload Endpoint ---
@app.route('/api/admin/upload', methods=['POST'])
@login_required
def upload_image():
    # Only allow admin and approved sellers to upload images
    if not (current_user.is_admin() or current_user.is_seller()):
        return jsonify({"error": "Access denied"}), 403
    
    try:
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
        """
        
        params = []
        if search_term:
            query += " WHERE p.name ILIKE %s OR p.description ILIKE %s"
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
@app.route('/api/admin/products', methods=['POST'])
@login_required
def create_product():
    # Only allow admin and approved sellers to create products
    if not (current_user.is_admin() or current_user.is_seller()):
        return jsonify({"error": "Access denied"}), 403
    
    try:
        data = request.get_json()
        
        if not data or not all(k in data for k in ['name', 'price', 'category', 'quantity']):
            return jsonify({"error": "Missing required fields"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Use default image if none provided
        image_url = data.get('image_url', '/static/default.png')
        
        # Insert product
        cursor.execute("""
            INSERT INTO products (name, description, price, category, image_url, created_by)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING product_id
        """, (data['name'], data.get('description', ''), data['price'], 
              data['category'], image_url, current_user.id))
        
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
@login_required
def update_product(product_id):
    # Only allow admin and approved sellers to update products
    if not (current_user.is_admin() or current_user.is_seller()):
        return jsonify({"error": "Access denied"}), 403
    
    try:
        data = request.get_json()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if product exists
        cursor.execute("SELECT 1 FROM products WHERE product_id = %s", (product_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Product not found"}), 404
        
        # Update product
        cursor.execute("""
            UPDATE products 
            SET name = %s, description = %s, price = %s, category = %s, image_url = %s
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
@login_required
def delete_product(product_id):
    # Only allow admin to delete products
    if not current_user.is_admin():
        return jsonify({"error": "Admin access required"}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if product exists
        cursor.execute("SELECT 1 FROM products WHERE product_id = %s", (product_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Product not found"}), 404
        
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
    print(f"🚀 Starting Flask app on port {port}")
    app.run(debug=False, host='0.0.0.0', port=port)