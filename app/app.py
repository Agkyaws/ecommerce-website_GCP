import os
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, g, send_from_directory, request

app = Flask(__name__)

# --- Database Connection (NOW FOR POSTGRESQL) ---

def get_db_connection():
    """Gets a new PostgreSQL connection."""
    if 'db_conn' not in g:
        g.db_conn = psycopg2.connect(
            host=os.environ.get('DB_HOST'),
            dbname=os.environ.get('DB_NAME'),
            user=os.environ.get('DB_USER'),
            password=os.environ.get('DB_PASS')
        )
    return g.db_conn

@app.teardown_appcontext
def close_connection(exception):
    """Closes the DB connection at the end of the request."""
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        db_conn.close()

def setup_database():
    """
    Creates the DB tables and inserts sample data.
    This should be run *once* (e.g., from a local machine or a K8s init job).
    For this demo, we'll keep the logic, but Cloud Run won't call it.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Drop tables to start fresh
    cursor.execute("DROP TABLE IF EXISTS inventory;")
    cursor.execute("DROP TABLE IF EXISTS products;")
    
    # Create 'products' table (using PostgreSQL syntax)
    cursor.execute('''
    CREATE TABLE products (
        product_id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        price REAL,
        category TEXT,
        image_url TEXT
    )
    ''')
    
    # Create 'inventory' table
    cursor.execute('''
    CREATE TABLE inventory (
        product_id INTEGER PRIMARY KEY,
        quantity INTEGER NOT NULL,
        FOREIGN KEY (product_id) REFERENCES products (product_id)
    )
    ''')

    # Sample products
    products_data = [
        ('Pro Laptop', 'A 16-inch high-performance laptop for professionals.', 1200.00, 'Electronics', 'static/p1.png'),
        ('Classic Coffee Mug', 'A sturdy 12oz ceramic mug, dishwasher safe.', 15.50, 'Homeware', 'static/p2.png'),
        ('Wireless Mouse', 'Ergonomic mouse with 8-button layout and 2-year battery life.', 75.00, 'Electronics', 'static/p3.png'),
        ('Cotton T-Shirt', '100% premium soft cotton. Pre-shrunk and tagless.', 20.00, 'Apparel', 'static/p4.png'),
        ('Running Shoes', 'Lightweight and breathable. Perfect for road running.', 89.99, 'Apparel', 'static/p5.png')
    ]
    
    # Use PostgreSQL-style executemany
    cursor.executemany("INSERT INTO products (name, description, price, category, image_url) VALUES (%s, %s, %s, %s, %s)", products_data)
    
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
    cursor.close()
    print("Database set up with 5 sample products and images.")

# --- Frontend Route (Unchanged) ---
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

# --- API Endpoints (Now for PostgreSQL) ---
@app.route('/api/products', methods=['GET'])
def get_products():
    search_term = request.args.get('search', '') 
    conn = get_db_connection()
    # Use RealDictCursor to get results as dictionaries
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
    return jsonify(products)

@app.route('/api/products/<int:product_id>/related', methods=['GET'])
def get_related_products(product_id):
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

# --- Run the App (for Cloud Run) ---
if __name__ == '__main__':
    # Cloud Run uses the 'PORT' environment variable
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=False, host='0.0.0.0', port=port)