# api_auth.py
from functools import wraps
from flask import request, jsonify, g
from psycopg2.extras import RealDictCursor
import os

def get_db_connection():
    """Reuse your existing DB connection function"""
    # You'll need to import or refactor this from app.py
    pass

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

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        user_info = validate_api_key(api_key)
        if not user_info:
            return jsonify({"error": "Invalid or expired API key"}), 401
        
        # Store user info in request context
        g.api_user = user_info
        return f(*args, **kwargs)
    
    return decorated_function

def admin_api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        user_info = validate_api_key(api_key)
        if not user_info:
            return jsonify({"error": "Invalid or expired API key"}), 401
        
        # Check if user is admin
        if user_info['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        # Store user info in request context
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
        
        # Check if user is admin or seller
        if user_info['role'] not in ['admin', 'seller']:
            return jsonify({"error": "Seller or Admin access required"}), 403
        
        g.api_user = user_info
        return f(*args, **kwargs)
    
    return decorated_function