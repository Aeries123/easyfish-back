from flask import Flask, request, jsonify,g,send_from_directory
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mysqldb import MySQL  # ✅ Correct MySQL import
from functools import wraps
from flask import request, jsonify
import jwt
import mysql.connector

from datetime import datetime, timedelta,timezone
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename
from MySQLdb.cursors import DictCursor  # ✅ Import DictCursor
from datetime import datetime, timedelta
import json
from flask_mysqldb import MySQL
import MySQLdb.cursors  # ✅ Import DictCursor





app = Flask(__name__)
CORS(app, supports_credentials=True, origins="http://localhost:3001")



# Set up MySQL configurations using environment variables
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)


UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
 
# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
 
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 

app.config['SECRET_KEY'] = 'your_secret_key'




def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', None)
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authorization header missing or malformed!"}), 403

        token = auth_header.split(" ")[1]

        try:
            # Decode the token using the secret key and check if it's valid
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

            # Check if the token is expired
            if datetime.now(timezone.utc) > datetime.fromtimestamp(payload['exp'], timezone.utc):
                return jsonify({"error": "Token has expired!"}), 401

            # Store the user data in Flask's g object
            g.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token!"}), 401
        except Exception as e:
            return jsonify({"error": f"An error occurred: {str(e)}"}), 500

        return f(*args, **kwargs)
    
    return decorated_function








#admin registeration

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')  # ⚠ Storing plain text password (Not Secure)
    phone = data.get('phone')
    role = data.get('role')

    if not (name and email and password and phone and role):
        return jsonify({"error": "All fields are required"}), 400

    try:
        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute("USE easyfish;")  # ✅ Explicitly select database

        # ✅ Check if the phone number already exists for the same role
        cursor.execute("SELECT phone FROM users WHERE phone = %s AND role = %s", (phone, role))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"error": f"Phone number already exists for role '{role}'. Please use a different number."}), 400

        # ✅ Insert new user
        cursor.execute("""
            INSERT INTO users (name, email, password, phone, role) 
            VALUES (%s, %s, %s, %s, %s)
        """, (name, email, password, phone, role))
        
        conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()



@app.route('/api/customers/register', methods=['POST'])  
def register_customer():
    try:
        # Get JSON data from request
        data = request.json
        
        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"'{field}' is required."}), 400
            
        name = data['name']
        email = data['email']
        phone = data['phone']
        password =data['password']  # Hash password before saving
       
        profile_picture = data.get('profile_picture', None)  # Optional field
        role = 'customer'  # Default role

        # Check if phone number already exists
        cursor = mysql.connection.cursor()
        check_phone_query = "SELECT COUNT(*) FROM users WHERE phone = %s"
        cursor.execute(check_phone_query, (phone,))
        phone_exists = cursor.fetchone()[0]
        
        if phone_exists > 0:
            return jsonify({"error": "Phone number already exists."}), 400

        # Insert into users table
        insert_user_query = """
            INSERT INTO users (name, email, phone, password, role) 
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(insert_user_query, (name, email, phone, password, role))
        mysql.connection.commit()
        user_id = cursor.lastrowid
        cursor.close()

        # Insert into customers table
        cursor = mysql.connection.cursor()
        insert_customer_query = """
            INSERT INTO customers (user_id, name, phone, email, password,profile_picture) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_customer_query, (user_id, name, phone, email, password, profile_picture))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Customer registered successfully."}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/api/customers', methods=['GET'])
def get_customers():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM customers")
        customers = cursor.fetchall()
        cursor.close()

        return jsonify(customers), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500




#admin login 
@app.route('/api/admin/login', methods=['POST'])
def login():
    data = request.json
    phone = data.get('phone')
    password = data.get('password')  # User-entered password

    try:
        conn = mysql.connection
        cursor = conn.cursor()
        
        # ✅ Fetch user by phone number
        cursor.execute("SELECT user_id, name, phone, password, role FROM users WHERE phone = %s", (phone,))
        user = cursor.fetchone()

        if user:
            user_id, name, phone, stored_password, role = user

            # ✅ Compare stored password with entered password
            if stored_password == password:  # ⚠ Plain text comparison (Not Secure)
                
                # 🔥 Generate JWT Token (Valid for 1 hour)
                token_payload = {
                    "user_id": user_id,
                    "name": name,
                    "phone": phone,
                    "role": role,
                    "exp": datetime.utcnow() + timedelta(hours=1)  # Token expiration time
                }
                token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

                return jsonify({
                    "message": "Login successful",
                    "token": token,
                    "user": {
                        "id": user_id,
                        "name": name,
                        "phone": phone,
                        "role": role
                    }
                }), 200
            
            else:
                return jsonify({"error": "Invalid phone number or password"}), 401
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()



#customer login

@app.route('/api/customer_login', methods=['POST'])
def customer_login():
    data = request.json
    phone = data.get('phone')
    password = data.get('password')
 
    if not (phone and password):
        return jsonify({"error": "Phone and password required"}), 400
 
    try:
        conn = mysql.connection
        cursor = conn.cursor()
 
        # ✅ Step 1: Fetch user credentials from `users` table
        cursor.execute("SELECT user_id, password FROM users WHERE phone = %s AND role = 'customer'", (phone,))
        user = cursor.fetchone()
 
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
 
        user_id, stored_password = user
 
        # ✅ Step 2: Directly compare passwords (⚠ Not secure, but per request)
        if stored_password != password:
            return jsonify({"error": "Invalid credentials"}), 401
 
        # ✅ Step 3: Fetch customer details from `customers` table using `user_id`
        cursor.execute("SELECT customer_id, name, email, profile_picture FROM customers WHERE user_id = %s", (user_id,))
        customer = cursor.fetchone()
 
        if not customer:
            return jsonify({"error": "Customer profile not found"}), 404
 
        customer_id, name, email, profile_picture = customer
 
        # ✅ Step 4: Fetch customer's home address from `addresses` table
        cursor.execute(
            "SELECT address, city, state, zip_code FROM addresses WHERE customer_id = %s AND address_type = 'home'",
            (customer_id,)
        )
        address_data = cursor.fetchone()
 
        address_info = {
            "address": address_data[0] if address_data else None,
            "city": address_data[1] if address_data else None,
            "state": address_data[2] if address_data else None,
            "zip_code": address_data[3] if address_data else None
        }
 
        # ✅ Step 5: Generate JWT token with required fields
        token_payload = {
            "role": "customer",
            "customer_id": customer_id,
            "customer_name": name,
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
 
        # ✅ Step 6: Construct response
        response_data = {
            "message": "Login successful",
            "customer_id": customer_id,
            "user_id": user_id,
            "name": name,
            "email": email,
            "phone": phone,
            "profile_picture": profile_picture,
            "role": "customer",
            "jwtToken": token,
            **address_info
        }
 
        return jsonify(response_data), 200
 
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
    finally:
        cursor.close()

@app.route('/api/customer_details', methods=['GET'])
@token_required
def get_customer_details():
    customer_id = g.user.get("customer_id")  # Access customer_id from token payload
 
    conn = mysql.connection
    cursor = conn.cursor()
 
    cursor.execute("SELECT name, email, profile_picture FROM customers WHERE customer_id = %s", (customer_id,))
    customer = cursor.fetchone()
 
    if not customer:
        return jsonify({"error": "Customer not found"}), 404
 
    name, email, profile_picture = customer
 
    return jsonify({
        "customer_id": customer_id,
        "customer_name": name,
        "email": email,
        "profile_picture": profile_picture
    }), 200
 



# ---------------------- Add Address ----------------------
@app.route('/api/addresses', methods=['POST'])
def add_address():
    data = request.json
    customer_id = data.get("customer_id")
    address = data.get("address")
    city = data.get("city")
    state = data.get("state")
    zip_code = data.get("zip_code")
    address_type = data.get("address_type", "home")  # Default to 'home'

    if not all([customer_id, address, city, state, zip_code]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO addresses (customer_id, address, city, state, zip_code, address_type) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (customer_id, address, city, state, zip_code, address_type))
        mysql.connection.commit()
        cur.close()

        return jsonify({"message": "Address added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------- Get All Addresses ----------------------
@app.route('/api/addresses', methods=['GET'])
def get_addresses():
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT a.address_id, c.name, a.address, a.city, a.state, a.zip_code, a.address_type, a.created_at
            FROM addresses a
            JOIN customers c ON a.customer_id = c.customer_id
        """)
        addresses = cur.fetchall()
        cur.close()

        return jsonify({
            "addresses": [
                {
                    "address_id": row[0],
                    "customer_name": row[1],
                    "address": row[2],
                    "city": row[3],
                    "state": row[4],
                    "zip_code": row[5],
                    "address_type": row[6],
                    "created_at": row[7].strftime('%Y-%m-%d %H:%M:%S')
                }
                for row in addresses
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500






# ---------------------- Update Address ----------------------
@app.route('/api/addresses/<int:address_id>', methods=['PUT'])
def update_address(address_id):
    data = request.json
    address = data.get("address")
    city = data.get("city")
    state = data.get("state")
    zip_code = data.get("zip_code")
    address_type = data.get("address_type", "home")

    if not all([address, city, state, zip_code]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE addresses 
            SET address = %s, city = %s, state = %s, zip_code = %s, address_type = %s 
            WHERE address_id = %s
        """, (address, city, state, zip_code, address_type, address_id))
        mysql.connection.commit()
        cur.close()

        return jsonify({"message": "Address updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# ---------------------- Delete Address ----------------------
@app.route('/api/addresses/<int:address_id>', methods=['DELETE'])
def delete_address(address_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM addresses WHERE address_id = %s", (address_id,))
        mysql.connection.commit()
        cur.close()

        return jsonify({"message": "Address deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500






@app.route('/api/test_category', methods=['POST'])
def add_test_category():
    try:
        # Get form data
        category_name = request.form.get('category_name')
        file = request.files.get('image')

        # Validate inputs
        if not category_name:
            return jsonify({"error": "Category name is required"}), 400
        if not file:
            return jsonify({"error": "Image file is required"}), 400

        # Check if category already exists
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM categories WHERE category_name = %s", (category_name,))
        existing_category = cursor.fetchone()
        cursor.close()

        if existing_category:
            return jsonify({"error": "Category name already exists. Please choose a different name."}), 400

        # Save the image file to the uploads folder
        if allowed_file(file.filename):
            filename = file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
        else:
            return jsonify({"error": "Invalid file type. Only PNG, JPG, JPEG, GIF are allowed."}), 400

        # Insert category and image path into the database
        cursor = mysql.connection.cursor()
        sql = "INSERT INTO categories (category_name, image) VALUES (%s, %s)"
        cursor.execute(sql, (category_name, filename))  # Pass both values
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Test category added successfully", "category_name": category_name, "image": filename}), 201

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500



#update_Categories

 
@app.route('/api/categories/<int:category_id>', methods=['PUT'])
def update_category(category_id):
    try:
        data = request.get_json()
        category_name = data.get("name")
 
        if not category_name:
            return jsonify({"error": "Category name is required"}), 400
 
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE categories SET name = %s WHERE id = %s", (category_name, category_id))
        mysql.connection.commit()
 
        if cursor.rowcount == 0:
            return jsonify({"message": "Category not found"}), 404
 
        cursor.close()
        return jsonify({"message": "Category updated successfully"}), 200
 
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
    
#delete_Categories

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
def delete_category(category_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM categories WHERE category_id = %s", (category_id,))
        mysql.connection.commit()

        if cursor.rowcount == 0:
            return jsonify({"message": "Category not found"}), 404

        cursor.close()
        return jsonify({"message": "Category deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500







#get_Categories
@app.route('/api/categories', methods=['GET'])
def get_categories():
    try:
        cursor = mysql.connection.cursor()

        # ✅ Log the current database name
        cursor.execute("SELECT DATABASE()")
        db_name = cursor.fetchone()
        print(f"Current Database: {db_name[0]}")

        # ✅ Fetch all categories
        query = "SELECT * FROM categories"
        cursor.execute(query)
        categories = cursor.fetchall()

        # ✅ Check if categories exist
        if not categories:
            return jsonify({"message": "No categories found"}), 404

        # ✅ Ensure cursor.description is not None before using it
        if cursor.description:
            column_names = [desc[0] for desc in cursor.description]
            base_url = "http://127.0.0.1:5000/static/uploads/"  # Change to your actual base URL

            formatted_categories = []
            for row in categories:
                category = dict(zip(column_names, row))
                
                # Convert image name to URL
                if "image" in category and category["image"]:
                    category["image"] = f"{base_url}{category['image']}"

                formatted_categories.append(category)
        else:
            return jsonify({"error": "Query execution failed, no metadata available"}), 500

        cursor.close()
        return jsonify({"categories": formatted_categories}), 200

    except Exception as e:
        print(f"Database Error: {e}")  # ✅ Log error for debugging
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500





@app.route('/api/orders_with_items', methods=['POST'])
def create_order_with_items():
    try:
        data = request.get_json()
        customer_id = data.get('customer_id')
        order_items = data.get('order_items', [])  # List of items

        if not customer_id or not order_items:
            return jsonify({"error": "Customer ID and order items are required"}), 400

        cursor = mysql.connection.cursor()

        # Check if the customer exists
        cursor.execute("SELECT customer_id FROM customers WHERE customer_id = %s", (customer_id,))
        customer = cursor.fetchone()
        if not customer:
            return jsonify({"error": "Customer not found"}), 404

        # Insert Order
        sql_order = "INSERT INTO orders (customer_id, total_price, status) VALUES (%s, %s, %s)"
        cursor.execute(sql_order, (customer_id, 0.00, 'Pending'))
        order_id = cursor.lastrowid

        total_price = 0

        # Insert Order Items
        for item in order_items:
            variant_id = item.get('variant_id')
            quantity = item.get('quantity')
            price = item.get('price')

            # Validate Variant ID
            cursor.execute("SELECT variant_id FROM product_variants WHERE variant_id = %s", (variant_id,))
            variant = cursor.fetchone()
            if not variant:
                return jsonify({"error": f"Variant ID {variant_id} not found"}), 404

            # Calculate total price
            total_price += quantity * price

            sql_order_item = "INSERT INTO order_items (order_id, variant_id, quantity, price) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql_order_item, (order_id, variant_id, quantity, price))

        # Update total price in the order
        cursor.execute("UPDATE orders SET total_price = %s WHERE order_id = %s", (total_price, order_id))

        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Order created successfully", "order_id": order_id}), 201

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({"error": str(e)}), 500

# Get All Orders
@app.route('/api/orders', methods=['GET'])
def get_orders():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT o.*, c.name AS customer_name FROM orders o JOIN customers c ON o.customer_id = c.customer_id")
        orders = cursor.fetchall()
        cursor.close()
       
        return jsonify(orders), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
 
 
 
 
# Get Order by ID with Order Items
@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
 
        # Fetch order details along with the customer name
        cursor.execute("""
            SELECT o.*, c.name AS customer_name
            FROM orders o
            JOIN customers c ON o.customer_id = c.customer_id
            WHERE o.order_id = %s
        """, (order_id,))
        order = cursor.fetchone()
 
        if not order:
            return jsonify({"error": "Order not found"}), 404
 
        # Fetch order items
        cursor.execute("""
            SELECT oi.order_item_id, oi.variant_id, oi.quantity, oi.price, oi.total
            FROM order_items oi
            WHERE oi.order_id = %s
        """, (order_id,))
        order_items = cursor.fetchall()
 
        cursor.close()
 
        # Add order items to the response
        order['order_items'] = order_items
 
        return jsonify(order), 200
 
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Update Order
@app.route('/api/orders/<int:order_id>', methods=['PUT'])
def update_order(order_id):
    try:
        data = request.get_json()
        total_price = data.get('total_price')
        status = data.get('status')
        
        cursor = mysql.connection.cursor()
        sql = "UPDATE orders SET total_price = %s, status = %s WHERE order_id = %s"
        cursor.execute(sql, (total_price, status, order_id))
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({"message": "Order updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500





# Delete Order
@app.route('/api/orders/<int:order_id>', methods=['DELETE'])
def delete_order(order_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM orders WHERE order_id = %s", (order_id,))
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({"message": "Order deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500





# 📌 Add Order Item
@app.route('/api/order_items', methods=['POST'])
def add_order_item():
    data = request.json
    order_id = data.get('order_id')
    variant_id = data.get('variant_id')
    quantity = data.get('quantity')
    price = data.get('price')

    if not order_id or not variant_id or not quantity or not price:
        return jsonify({"error": "Missing required fields"}), 400

    total = quantity * price

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO order_items (order_id, variant_id, quantity, price) VALUES (%s, %s, %s, %s)",
            (order_id, variant_id, quantity, price)
        )
        mysql.connection.commit()
        order_item_id = cur.lastrowid
        cur.close()

        return jsonify({"message": "Order item added successfully", "order_item_id": order_item_id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500




# 📌 Get All Order Items
@app.route('/api/order_items', methods=['GET'])
def get_order_items():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM order_items")
        rows = cur.fetchall()
        cur.close()

        order_items = [
            {"order_item_id": row[0], "order_id": row[1], "variant_id": row[2], "quantity": row[3], "price": row[4], "total": row[3] * row[4]}
            for row in rows
        ]

        return jsonify(order_items), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 📌 Get Order Items by Order ID
@app.route('/api/order_items/<int:order_id>', methods=['GET'])
def get_order_items_by_order(order_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM order_items WHERE order_id = %s", (order_id,))
        rows = cur.fetchall()
        cur.close()

        if not rows:
            return jsonify({"error": "No order items found for this order"}), 404

        order_items = [
            {"order_item_id": row[0], "variant_id": row[2], "quantity": row[3], "price": row[4], "total": row[3] * row[4]}
            for row in rows
        ]

        return jsonify({"order_id": order_id, "items": order_items}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 📌 Update an Order Item
@app.route('/api/order_items/<int:order_item_id>', methods=['PUT'])
def update_order_item(order_item_id):
    data = request.json
    quantity = data.get('quantity')
    price = data.get('price')

    if not quantity or not price:
        return jsonify({"error": "Quantity and price are required"}), 400

    total = quantity * price

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE order_items SET quantity = %s, price = %s WHERE order_item_id = %s",
            (quantity, price, order_item_id)
        )
        mysql.connection.commit()
        cur.close()

        return jsonify({"message": "Order item updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 📌 Delete an Order Item
@app.route('/api/order_items/<int:order_item_id>', methods=['DELETE'])
def delete_order_item(order_item_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM order_items WHERE order_item_id = %s", (order_item_id,))
        mysql.connection.commit()
        cur.close()

        return jsonify({"message": "Order item deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500






# 📌 Add Product
@app.route('/api/products', methods=['POST'])
def add_product():
    data = request.json
    category_id = data.get('category_id')
    product_name = data.get('product_name')
    description = data.get('description', '')
    added_by = data.get('added_by')

    if not category_id or not product_name or not added_by:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO products (category_id, product_name, description, added_by) VALUES (%s, %s, %s, %s)",
            (category_id, product_name, description, added_by)
        )
        mysql.connection.commit()
        product_id = cur.lastrowid
        cur.close()

        return jsonify({"message": "Product added successfully", "product_id": product_id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500




  # 📌 Get All Products


#admin get products 

@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        cur = mysql.connection.cursor()

        # ✅ Fetch all product details
        cur.execute("""
            SELECT p.product_id, p.product_name, p.description, p.is_available, 
                   c.category_name
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.category_id
        """)
        products_data = cur.fetchall()
        product_columns = [desc[0] for desc in cur.description]  # Get column names

        # ✅ Fetch product images
        cur.execute("SELECT product_id, image_url FROM product_images")
        images_data = cur.fetchall()
        image_columns = [desc[0] for desc in cur.description]  # Get column names

        # ✅ Fetch stock, weight, and price details
        cur.execute("SELECT id, product_id, weight, stock, price FROM product_stock")
        stock_data = cur.fetchall()
        stock_columns = [desc[0] for desc in cur.description]  # Get column names

        cur.close()

        # ✅ Base URL for images (change as needed)
        base_url = "http://127.0.0.1:5000/static/uploads/"

        # ✅ Convert fetched data into dictionaries
        products_data = [dict(zip(product_columns, row)) for row in products_data]
        images_data = [dict(zip(image_columns, row)) for row in images_data]
        stock_data = [dict(zip(stock_columns, row)) for row in stock_data]

        # ✅ Process products
        products = {}
        for row in products_data:
            product_id = row["product_id"]
            if product_id not in products:
                products[product_id] = {
                    "id": product_id,
                    "name": row["product_name"],
                    "category": row["category_name"],
                    "stock": 0,  # Will be updated from stock_data
                    "ratings": 4.5,  # Placeholder (Adjust if needed)
                    "images": [],
                    "description": row["description"],
                    "isAvailable": bool(row["is_available"]),
                    "quantity": 1,
                    "quantityByWeight": [],
                    "defaultPrice": None,
                    "defaultWeight": None,
                    "defaultWeightId": None
                }

        # ✅ Add images to products
        for image in images_data:
            product_id = image["product_id"]
            if product_id in products and image["image_url"]:
                products[product_id]["images"].append(f"{base_url}{image['image_url']}")

        # ✅ Add stock, weight, and price details
        for stock in stock_data:
            product_id = stock["product_id"]
            stock_entry = {
                "weight": stock["weight"],
                "quantity": stock["stock"],
                "price": float(stock["price"]),
                "id": stock["id"] 
            }
            if product_id in products:
                products[product_id]["quantityByWeight"].append(stock_entry)

                # ✅ Update stock count (sum of all weights)
                products[product_id]["stock"] += stock["stock"]

                # ✅ Set default weight & price (first available option)
                if not products[product_id]["defaultPrice"]:
                    products[product_id]["defaultPrice"] = float(stock["price"])
                    products[product_id]["defaultWeight"] = stock["weight"]
                    products[product_id]["defaultWeightId"] = str(stock["id"])

        return jsonify(list(products.values())), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




# 📌 Get Product by ID
@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT p.product_id, p.category_id, c.category_name, p.product_name, p.description, p.added_by, p.created_at
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.category_id
            WHERE p.product_id = %s
        """, (product_id,))
        row = cur.fetchone()
        cur.close()

        if not row:
            return jsonify({"error": "Product not found"}), 404

        product = {
            "product_id": row[0], "category_id": row[1], "category_name": row[2],
            "product_name": row[3], "description": row[4], "added_by": row[5], "created_at": row[6]
        }

        return jsonify(product), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 📌 Update Product
@app.route('/api/products/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    data = request.json
    category_id = data.get('category_id')
    product_name = data.get('product_name')
    description = data.get('description', '')
    added_by = data.get('added_by')

    if not category_id or not product_name or not added_by:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE products SET category_id = %s, product_name = %s, description = %s, added_by = %s WHERE product_id = %s",
            (category_id, product_name, description, added_by, product_id)
        )
        mysql.connection.commit()
        cur.close()

        return jsonify({"message": "Product updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 📌 Delete Product
@app.route('/api/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM products WHERE product_id = %s", (product_id,))
        mysql.connection.commit()
        cur.close()

        return jsonify({"message": "Product deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500





# ✅ Add a Variant (Ensures product_id Exists)
@app.route('/api/variants', methods=['POST'])
def add_variant():
    data = request.json
    product_id = data.get('product_id')
    weight = data.get('weight')
    price = data.get('price')
    available_stock = data.get('available_stock')

    if not product_id or weight is None or price is None or available_stock is None:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        cur = mysql.connection.cursor()
        
        # 🔹 Check if product_id exists
        cur.execute("SELECT COUNT(*) FROM products WHERE product_id = %s", (product_id,))
        result = cur.fetchone()
        if result[0] == 0:
            return jsonify({"error": "Invalid product_id"}), 400

        # 🔹 Insert Variant Data
        cur.execute(
            "INSERT INTO product_variants (product_id, weight, price, available_stock) VALUES (%s, %s, %s, %s)",
            (product_id, weight, price, available_stock)
        )
        mysql.connection.commit()
        variant_id = cur.lastrowid
        cur.close()

        return jsonify({"message": "Variant added successfully", "variant_id": variant_id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/api/variants', methods=['GET'])
def get_variants():
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT v.variant_id, v.product_id, p.product_name, v.weight, v.price, v.available_stock 
            FROM product_variants v 
            JOIN products p ON v.product_id = p.product_id
        """)
        variants = cur.fetchall()
        cur.close()

        variant_list = []
        for row in variants:
            variant_list.append({
                "variant_id": row[0],
                "product_id": row[1],
                "product_name": row[2],
                "weight": float(row[3]),
                "price": float(row[4]),
                "available_stock": float(row[5])
            })

        return jsonify({"variants": variant_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/variants/<int:product_id>', methods=['GET'])
def get_variants_by_product(product_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT variant_id, product_id, weight, price, available_stock 
            FROM product_variants 
            WHERE product_id = %s
        """, (product_id,))
        variants = cur.fetchall()
        cur.close()

        if not variants:
            return jsonify({"error": "No variants found for this product"}), 404

        variant_list = [{"variant_id": row[0], "weight": float(row[2]), "price": float(row[3]), "available_stock": float(row[4])} for row in variants]

        return jsonify({"variants": variant_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500






if __name__ == '__main__':
    app.run(debug=True)

