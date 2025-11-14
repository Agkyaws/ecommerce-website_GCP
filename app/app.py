import os
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, g, send_from_directory, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import time
import uuid
from werkzeug.utils import secure_filename
from flasgger import Swagger, swag_from

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'serve_index'

# Initialize Swagger
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
    "specs_route": "/api-docs/"
}
swagger = Swagger(app, config=swagger_config)

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
@swag_from({
    'tags': ['System'],
    'summary': 'Health check endpoint',
    'description': 'Check the health status of the application and database connection',
    'responses': {
        200: {
            'description': 'Application is healthy',
            'schema': {
                'type': 'object',
                'properties': {
                    'status': {
                        'type': 'string',
                        'example': 'healthy'
                    },
                    'database': {
                        'type': 'string',
                        'example': 'connected'
                    },
                    'db_host': {
                        'type': 'string',
                        'example': '10.0.2.3'
                    }
                }
            }
        },
        500: {
            'description': 'Application is unhealthy',
            'schema': {
                'type': 'object',
                'properties': {
                    'status': {
                        'type': 'string',
                        'example': 'unhealthy'
                    },
                    'database': {
                        'type': 'string',
                        'example': 'disconnected'
                    },
                    'error': {
                        'type': 'string',
                        'example': 'Connection timeout'
                    }
                }
            }
        }
    }
})
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

# --- Authentication Endpoints ---
@app.route('/api/register', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Register a new user',
    'description': 'Create a new user account with username, email, and password',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {
                        'type': 'string',
                        'description': 'Unique username',
                        'example': 'john_doe'
                    },
                    'email': {
                        'type': 'string',
                        'format': 'email',
                        'description': 'Valid email address',
                        'example': 'john@example.com'
                    },
                    'password': {
                        'type': 'string',
                        'description': 'Password (min 6 characters)',
                        'example': 'password123'
                    },
                    'role': {
                        'type': 'string',
                        'description': 'User role (user, seller, admin)',
                        'default': 'user',
                        'example': 'user'
                    }
                },
                'required': ['username', 'email', 'password']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'User registered successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'User registered successfully'
                    },
                    'user_id': {
                        'type': 'integer',
                        'example': 4
                    },
                    'needs_approval': {
                        'type': 'boolean',
                        'example': False
                    }
                }
            }
        },
        400: {
            'description': 'Missing required fields or username/email already exists',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Missing required fields'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Login to existing account',
    'description': 'Authenticate with username and password',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {
                        'type': 'string',
                        'description': 'Registered username',
                        'example': 'john_doe'
                    },
                    'password': {
                        'type': 'string',
                        'description': 'Account password',
                        'example': 'password123'
                    }
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Login successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Login successful'
                    },
                    'user': {
                        'type': 'object',
                        'properties': {
                            'user_id': {
                                'type': 'integer',
                                'example': 1
                            },
                            'username': {
                                'type': 'string',
                                'example': 'admin'
                            },
                            'email': {
                                'type': 'string',
                                'example': 'admin@shop.com'
                            },
                            'role': {
                                'type': 'string',
                                'example': 'admin'
                            }
                        }
                    }
                }
            }
        },
        401: {
            'description': 'Invalid credentials',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Invalid username or password'
                    }
                }
            }
        },
        403: {
            'description': 'Account not approved',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Account pending approval'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Logout from current session',
    'description': 'End the current user session',
    'responses': {
        200: {
            'description': 'Logout successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Logout successful'
                    }
                }
            }
        }
    }
})
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"}), 200

@app.route('/api/user')
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Get current user information',
    'description': 'Retrieve details about the currently authenticated user',
    'responses': {
        200: {
            'description': 'User details',
            'schema': {
                'type': 'object',
                'properties': {
                    'user_id': {
                        'type': 'integer',
                        'example': 1
                    },
                    'username': {
                        'type': 'string',
                        'example': 'admin'
                    },
                    'email': {
                        'type': 'string',
                        'example': 'admin@shop.com'
                    },
                    'role': {
                        'type': 'string',
                        'example': 'admin'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['User Management'],
    'summary': 'List all users',
    'description': 'Retrieve a list of all users in the system (admin only)',
    'responses': {
        200: {
            'description': 'List of users',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'user_id': {
                            'type': 'integer',
                            'example': 1
                        },
                        'username': {
                            'type': 'string',
                            'example': 'admin'
                        },
                        'email': {
                            'type': 'string',
                            'example': 'admin@shop.com'
                        },
                        'role': {
                            'type': 'string',
                            'example': 'admin'
                        },
                        'approved': {
                            'type': 'boolean',
                            'example': True
                        },
                        'created_at': {
                            'type': 'string',
                            'format': 'date-time',
                            'example': '2023-10-15T12:34:56Z'
                        }
                    }
                }
            }
        },
        403: {
            'description': 'Admin access required',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Admin access required'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['User Management'],
    'summary': 'Approve a user account',
    'description': 'Approve a user account that is pending approval (admin only)',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to approve',
            'example': 2
        }
    ],
    'responses': {
        200: {
            'description': 'User approved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'User approved successfully'
                    }
                }
            }
        },
        403: {
            'description': 'Admin access required',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Admin access required'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['User Management'],
    'summary': 'Update user role',
    'description': 'Change a user\'s role (admin only)',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to update',
            'example': 2
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'role': {
                        'type': 'string',
                        'description': 'New role for the user',
                        'enum': ['user', 'seller', 'admin'],
                        'example': 'seller'
                    }
                },
                'required': ['role']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'User role updated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'User role updated successfully'
                    }
                }
            }
        },
        400: {
            'description': 'Invalid role specified',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Invalid role'
                    }
                }
            }
        },
        403: {
            'description': 'Admin access required',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Admin access required'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['User Management'],
    'summary': 'Delete a user account',
    'description': 'Delete a user account (admin only). Cannot delete users who have created products or your own account.',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to delete',
            'example': 2
        }
    ],
    'responses': {
        200: {
            'description': 'User deleted successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'User deleted successfully'
                    }
                }
            }
        },
        400: {
            'description': 'Cannot delete user with products or self',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Cannot delete user who has created products'
                    }
                }
            }
        },
        403: {
            'description': 'Admin access required',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Admin access required'
                    }
                }
            }
        },
        404: {
            'description': 'User not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'User not found'
                    }
                }
            }
        }
    }
})
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        return jsonify({"error": "Admin access required"}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT 1 FROM users WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            return jsonify({"error": "User not found"}), 404
        
        # Check if user has created any products (prevent deletion if they have)
        cursor.execute("SELECT 1 FROM products WHERE created_by = %s LIMIT 1", (user_id,))
        if cursor.fetchone():
            return jsonify({"error": "Cannot delete user who has created products"}), 400
        
        # Prevent admin from deleting themselves
        if user_id == current_user.id:
            return jsonify({"error": "Cannot delete your own account"}), 400
            
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
@swag_from({
    'tags': ['Product Management'],
    'summary': 'Upload product image',
    'description': 'Upload an image for product (admin or approved sellers only)',
    'parameters': [
        {
            'name': 'image',
            'in': 'formData',
            'type': 'file',
            'required': True,
            'description': 'Image file to upload (PNG, JPG, JPEG, GIF, WEBP)'
        }
    ],
    'responses': {
        200: {
            'description': 'Image uploaded successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Image uploaded successfully'
                    },
                    'image_url': {
                        'type': 'string',
                        'example': '/static/uploads/abcd1234_product.jpg'
                    }
                }
            }
        },
        400: {
            'description': 'Invalid file or no file provided',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'No file part'
                    }
                }
            }
        },
        403: {
            'description': 'Access denied (not admin or seller)',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Access denied'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['Product Management'],
    'summary': 'Get all products',
    'description': 'Retrieve all products with optional search filtering',
    'parameters': [
        {
            'name': 'search',
            'in': 'query',
            'type': 'string',
            'description': 'Filter products by name or description',
            'example': 'laptop'
        },
        {
            'name': 'admin',
            'in': 'query',
            'type': 'string',
            'description': 'Set to "true" to include inventory quantities',
            'example': 'true'
        }
    ],
    'responses': {
        200: {
            'description': 'List of products',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'product_id': {
                            'type': 'integer',
                            'example': 1
                        },
                        'name': {
                            'type': 'string',
                            'example': 'Pro Laptop'
                        },
                        'description': {
                            'type': 'string',
                            'example': 'A 16-inch high-performance laptop for professionals.'
                        },
                        'price': {
                            'type': 'number',
                            'format': 'float',
                            'example': 1200.00
                        },
                        'category': {
                            'type': 'string',
                            'example': 'Electronics'
                        },
                        'image_url': {
                            'type': 'string',
                            'example': '/static/p1.png'
                        },
                        'quantity': {
                            'type': 'integer',
                            'example': 5
                        },
                        'stock_status': {
                            'type': 'string',
                            'example': 'In Stock'
                        }
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['Product Management'],
    'summary': 'Get related products',
    'description': 'Get products from the same category as the specified product',
    'parameters': [
        {
            'name': 'product_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the product to find related products for',
            'example': 1
        }
    ],
    'responses': {
        200: {
            'description': 'List of related products',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'product_id': {
                            'type': 'integer',
                            'example': 2
                        },
                        'name': {
                            'type': 'string',
                            'example': 'Wireless Mouse'
                        },
                        'price': {
                            'type': 'number',
                            'format': 'float',
                            'example': 75.00
                        },
                        'category': {
                            'type': 'string',
                            'example': 'Electronics'
                        },
                        'image_url': {
                            'type': 'string',
                            'example': '/static/p3.png'
                        }
                    }
                }
            }
        },
        404: {
            'description': 'Product not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Product not found'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['Product Management'],
    'summary': 'Create a new product',
    'description': 'Create a new product (admin or approved sellers only)',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {
                        'type': 'string',
                        'description': 'Product name',
                        'example': 'New Product'
                    },
                    'description': {
                        'type': 'string',
                        'description': 'Product description',
                        'example': 'Product description'
                    },
                    'price': {
                        'type': 'number',
                        'format': 'float',
                        'description': 'Product price',
                        'example': 99.99
                    },
                    'category': {
                        'type': 'string',
                        'description': 'Product category',
                        'example': 'Electronics'
                    },
                    'image_url': {
                        'type': 'string',
                        'description': 'URL of product image',
                        'example': '/static/new-product.png'
                    },
                    'quantity': {
                        'type': 'integer',
                        'description': 'Initial stock quantity',
                        'example': 10
                    }
                },
                'required': ['name', 'price', 'category', 'quantity']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Product created successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Product created successfully'
                    },
                    'product_id': {
                        'type': 'integer',
                        'example': 6
                    }
                }
            }
        },
        400: {
            'description': 'Missing required fields',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Missing required fields'
                    }
                }
            }
        },
        403: {
            'description': 'Access denied (not admin or seller)',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Access denied'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['Product Management'],
    'summary': 'Update an existing product',
    'description': 'Update product details (admin or approved sellers only)',
    'parameters': [
        {
            'name': 'product_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the product to update',
            'example': 1
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {
                        'type': 'string',
                        'description': 'Product name',
                        'example': 'Updated Product'
                    },
                    'description': {
                        'type': 'string',
                        'description': 'Product description',
                        'example': 'Updated description'
                    },
                    'price': {
                        'type': 'number',
                        'format': 'float',
                        'description': 'Product price',
                        'example': 89.99
                    },
                    'category': {
                        'type': 'string',
                        'description': 'Product category',
                        'example': 'Electronics'
                    },
                    'image_url': {
                        'type': 'string',
                        'description': 'URL of product image',
                        'example': '/static/updated-product.png'
                    },
                    'quantity': {
                        'type': 'integer',
                        'description': 'Stock quantity',
                        'example': 15
                    }
                },
                'required': ['name', 'price', 'category', 'quantity']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Product updated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Product updated successfully'
                    }
                }
            }
        },
        400: {
            'description': 'Missing required fields',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Missing required fields'
                    }
                }
            }
        },
        403: {
            'description': 'Access denied (not admin or seller)',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Access denied'
                    }
                }
            }
        },
        404: {
            'description': 'Product not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Product not found'
                    }
                }
            }
        }
    }
})
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
@swag_from({
    'tags': ['Product Management'],
    'summary': 'Delete a product',
    'description': 'Delete a product (admin only)',
    'parameters': [
        {
            'name': 'product_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the product to delete',
            'example': 1
        }
    ],
    'responses': {
        200: {
            'description': 'Product deleted successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Product deleted successfully'
                    }
                }
            }
        },
        403: {
            'description': 'Admin access required',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Admin access required'
                    }
                }
            }
        },
        404: {
            'description': 'Product not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'example': 'Product not found'
                    }
                }
            }
        }
    }
})
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