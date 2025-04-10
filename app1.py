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
import json
import MySQLdb.cursors  # ✅ Import DictCursor
# import datetime


app = Flask(__name__)
CORS(app, supports_credentials=True, origins="http://localhost:3004")

# Set up MySQL configurations using environment variables
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)

# SECRET_KEY = 'your_very_secret_key'


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
        # Check if request is JSON
        if not request.is_json:
            return jsonify({"error": "Invalid request format. Expected JSON."}), 400

        data = request.get_json()

        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'password', 'address']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"'{field}' is required."}), 400

        name = data['name']
        email = data['email']
        phone = data['phone']
        password = data['password']  # Hash before saving
        role = 'customer'
        profile_picture = data.get('profile_picture', None)

        # Ensure address is a list
        if not isinstance(data['address'], list) or len(data['address']) == 0:
            return jsonify({"error": "'address' must be a non-empty list."}), 400

        # Validate each address entry
        for addr in data['address']:
            for field in ['address', 'city', 'state', 'zip_code']:
                if field not in addr or not addr[field]:
                    return jsonify({"error": f"'{field}' is required in address."}), 400

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

        # Insert into customers table
        insert_customer_query = """
            INSERT INTO customers (user_id, name, phone, email, password, profile_picture) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_customer_query, (user_id, name, phone, email, password, profile_picture))
        mysql.connection.commit()
        customer_id = cursor.lastrowid

        # Insert each address into addresses table
        insert_address_query = """
            INSERT INTO addresses (customer_id, address, city, state, zip_code, address_type) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        for addr in data['address']:
            cursor.execute(insert_address_query, (
                customer_id, addr['address'], addr['city'], addr['state'], addr['zip_code'], addr.get('address_type', 'home')
            ))

        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Customer registered successfully."}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500



#admin get_customers
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

#admin get_payments


# Get all payments
@app.route('/api/payments', methods=['GET'])
def get_payments():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT p.payment_id, p.order_id, c.name, p.amount, 
                   p.payment_method, p.transaction_id, p.status, p.created_at
            FROM payments p
            JOIN customers c ON p.customer_id = c.customer_id
        """)
        payments = cursor.fetchall()
        cursor.close()

        return jsonify(payments), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



#admin get_payments/date

@app.route('/api/payments/date', methods=['GET'])
def get_all_payments():
    try:
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')

        # ✅ Validate date parameters
        if not from_date or not to_date:
            return jsonify({"error": "Both from_date and to_date are required"}), 400

        try:
            from_date = datetime.strptime(from_date, "%Y-%m-%d").date()
            to_date = datetime.strptime(to_date, "%Y-%m-%d").date()
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

        if to_date < from_date:
            return jsonify({"error": "to_date cannot be before from_date"}), 400

        # ✅ SQL Query with date filtering
        query = """
            SELECT p.payment_id, p.order_id, c.name AS customer_name, p.amount, 
                   p.payment_method, p.transaction_id, p.status, p.created_at
            FROM payments p
            JOIN customers c ON p.customer_id = c.customer_id
            WHERE DATE(p.created_at) BETWEEN %s AND %s
            ORDER BY p.created_at DESC
        """

        params = [from_date, to_date]

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(query, params)
        payments = cursor.fetchall()
        cursor.close()

        return jsonify(payments), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/api/payments/<int:payment_id>', methods=['GET'])
def get_payment(payment_id):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT p.payment_id, p.order_id, c.name, c.email, c.phone,
                   p.amount, p.payment_method, p.transaction_id, p.status, p.created_at,
                   o.order_date, o.total_price, o.status
            FROM payments p
            JOIN customers c ON p.customer_id = c.customer_id
            JOIN orders o ON p.order_id = o.order_id
            WHERE p.payment_id = %s
        """, (payment_id,))
        
        payment = cursor.fetchone()
        cursor.close()

        if payment:
            return jsonify(payment), 200
        else:
            return jsonify({"error": "Payment not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/reviews', methods=['GET'])
def get_reviews():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT r.review_id, c.name AS customer_name, c.email, c.phone, 
                   r.rating, r.review_text, r.created_at
            FROM reviews r
            JOIN customers c ON r.customer_id = c.customer_id
            ORDER BY r.created_at DESC
        """)
        reviews = cursor.fetchall()
        cursor.close()

        return jsonify(reviews), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/reviews/date', methods=['GET'])
def get_all_reviews():
    try:
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
 
        if not from_date or not to_date:
            return jsonify({"error": "Both from_date and to_date are required"}), 400
 
        try:
            from_date = datetime.strptime(from_date, "%Y-%m-%d").date()
            to_date = datetime.strptime(to_date, "%Y-%m-%d").date()
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
 
        if to_date < from_date:
            return jsonify({"error": "to_date cannot be before from_date"}), 400
 
        query = """
            SELECT r.review_id, c.name AS customer_name, c.email, c.phone,
                   r.rating, r.review_text, r.created_at
            FROM reviews r
            JOIN customers c ON r.customer_id = c.customer_id
            WHERE DATE(r.created_at) BETWEEN %s AND %s
            ORDER BY r.created_at DESC
        """
 
        filters = [from_date, to_date]
 
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(query, filters)
        reviews = cursor.fetchall()
        cursor.close()
 
        return jsonify(reviews), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
 

@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
def delete_review(review_id):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Check if the review exists
        cursor.execute("SELECT * FROM reviews WHERE review_id = %s", (review_id,))
        review = cursor.fetchone()
        if not review:
            return jsonify({"error": "Review not found"}), 404

        # Delete the review
        cursor.execute("DELETE FROM reviews WHERE review_id = %s", (review_id,))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Review deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/orders', methods=['GET']) 
def get_all_orders():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # ✅ Fetch all orders, now including delivery boy name
        cursor.execute("""
            SELECT
                o.order_id, o.order_date, o.total_price, o.status,
                o.assign,
                o.delivery_boy_id,
                db.name AS delivery_boy_name,
                c.customer_id, c.name AS customer_name
            FROM orders o
            JOIN customers c ON o.customer_id = c.customer_id
            LEFT JOIN delivery_boys db ON o.delivery_boy_id = db.delivery_boy_id
            ORDER BY o.order_id DESC;
        """)

        orders_data = cursor.fetchall()

        if not orders_data:
            return jsonify([]), 200

        order_ids = tuple(order["order_id"] for order in orders_data)
        if not order_ids:
            return jsonify(orders_data), 200

        query_placeholders = ', '.join(['%s'] * len(order_ids))
        cursor.execute(f"""
            SELECT
                oi.order_item_id, oi.order_id, oi.quantity, oi.price AS item_price, oi.total AS item_total,
                p.product_id, p.product_name, p.description,
                ps.weight, ps.stock AS stock_quantity, ps.price AS variant_price
            FROM order_items oi
            JOIN product_stock ps ON oi.variant_id = ps.id
            JOIN products p ON ps.product_id = p.product_id
            WHERE oi.order_id IN ({query_placeholders})
        """, order_ids)
        order_items_data = cursor.fetchall()

        cursor.execute("SELECT product_id, image_url FROM product_images")
        images_data = cursor.fetchall()
        cursor.close()

        base_url = "http://127.0.0.1:5000/static/uploads/"

        orders = {row["order_id"]: {
            "order_id": row["order_id"],
            "order_date": row["order_date"],
            "total_price": row["total_price"],
            "status": row["status"],
            "assign": row["assign"],
            "delivery_boy_name": row["delivery_boy_name"],  # ✅ Include delivery boy name
            "customer": {
                "customer_id": row["customer_id"],
                "name": row["customer_name"]
            },
            "items": []
        } for row in orders_data}

        product_images = {}
        for img in images_data:
            product_id = img["product_id"]
            if product_id not in product_images:
                product_images[product_id] = []
            if img["image_url"]:
                product_images[product_id].append(f"{base_url}{img['image_url']}")

        for item in order_items_data:
            order_id = item["order_id"]
            product_id = item["product_id"]
            order_item = {
                "order_item_id": item["order_item_id"],
                "product_id": product_id,
                "product_name": item["product_name"],
                "description": item["description"],
                "quantity": item["quantity"],
                "item_price": float(item["item_price"]),
                "item_total": float(item["item_total"]),
                "variant": {
                    "weight": item["weight"],
                    "stock_quantity": item["stock_quantity"],
                    "price": float(item["variant_price"])
                },
                "images": product_images.get(product_id, [])
            }
            orders[order_id]["items"].append(order_item)

        return jsonify(list(orders.values())), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/api/orders/assigned', methods=['GET'])
def get_assigned_orders():
    try:
        # Use DictCursor for dictionary-style results
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        query = """
            SELECT 
                o.order_id,
                o.customer_id,
                o.total_price,
                o.status,
                o.order_date,
                o.delivery_boy_id,
                o.assign,
                c.name AS customer_name,
                d.name AS delivery_boy_name
            FROM orders o
            LEFT JOIN customers c ON o.customer_id = c.customer_id
            LEFT JOIN delivery_boys d ON o.delivery_boy_id = d.delivery_boy_id
            WHERE o.assign = 'assigned'
            ORDER BY o.order_date DESC
        """
        cursor.execute(query)
        orders = cursor.fetchall()
        cursor.close()

        formatted_orders = [
            {
                'order_id': order['order_id'],
                'customer': {
                    'name': order['customer_name']
                },
                'order_date': order['order_date'],
                'assign': order['assign'],
                'delivery_boy_name': order['delivery_boy_name'],
                'status': order['status'],
                'total_price': float(order['total_price']) if order['total_price'] else 0.0
            }
            for order in orders
        ]

        return jsonify(formatted_orders), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
# @app.route('/api/orders', methods=['POST'])
# @token_required
# def place_order():
#     try:
#         data = request.json
#         total_price = data.get("total_price")
#         order_items = data.get("items")
 
#         if not total_price or not order_items:
#             return jsonify({"error": "Missing required fields"}), 400
 
#         user_id = g.user["user_id"]  # Extract user ID from token
#         customer_id = g.user["customer_id"]  # Extract customer ID from token
#         customer_name = g.user["customer_name"]  # Extract customer name from token
 
#         cur = mysql.connection.cursor()
 
#         # ✅ Insert order
#         insert_order_query = """
#             INSERT INTO orders (customer_id, total_price, status)
#             VALUES (%s, %s, %s)
#         """
#         cur.execute(insert_order_query, (customer_id, total_price, "Pending"))
#         order_id = cur.lastrowid  # Get newly inserted order ID
 
#         # ✅ Insert order items
#         insert_order_item_query = """
#             INSERT INTO order_items (order_id, variant_id, quantity, price, total)
#             VALUES (%s, %s, %s, %s, %s)
#         """
#         for item in order_items:
#             cur.execute(insert_order_item_query,
#                         (order_id, item["variant_id"], item["quantity"], item["price"], item["total"]))
 
#         # ✅ Insert notification for Admin
#         admin_id = 14  # Replace with actual admin user ID if dynamic
#         admin_message = f"New order received. Order ID: {order_id}, Customer: {customer_name}."
#         insert_admin_notification_query = """
#             INSERT INTO notifications (user_id, title, message, is_read, created_at)
#             VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
#         """
#         cur.execute(insert_admin_notification_query, (admin_id, "New Order", admin_message, 0))
 
#         # ✅ Insert notification for Customer
#         customer_message = f"Your order has been placed successfully. Order ID: {order_id}."
#         insert_customer_notification_query = """
#             INSERT INTO notifications (user_id, title, message, is_read, created_at)
#             VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
#         """
#         cur.execute(insert_customer_notification_query, (user_id, "Order Confirmation", customer_message, 0))
 
#         mysql.connection.commit()
#         cur.close()
 
#         return jsonify({"message": "Order placed successfully", "order_id": order_id}), 201
 
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500



# @app.route('/api/orders', methods=['POST'])
# @token_required
# def place_order():
#     try:
#         data = request.json
#         total_price = data.get("total_price")
#         order_items = data.get("items")
#         payment_method = data.get("payment_method")
#         transaction_id = data.get("transaction_id")

#         if not total_price or not order_items or not payment_method:
#             return jsonify({"error": "Missing required fields"}), 400

#         user_id = g.user["user_id"]  # Extract user ID from token
#         customer_id = g.user["customer_id"]  # Extract customer ID from token
#         customer_name = g.user["customer_name"]  # Extract customer name from token

#         cur = mysql.connection.cursor()

#         # ✅ Insert order
#         insert_order_query = """
#             INSERT INTO orders (customer_id, total_price, status)
#             VALUES (%s, %s, %s)
#         """
#         cur.execute(insert_order_query, (customer_id, total_price, "Pending"))
#         order_id = cur.lastrowid  # Get newly inserted order ID

#         # ✅ Insert order items
#         insert_order_item_query = """
#             INSERT INTO order_items (order_id, variant_id, quantity, price, total)
#             VALUES (%s, %s, %s, %s, %s)
#         """
#         for item in order_items:
#             cur.execute(insert_order_item_query,
#                         (order_id, item["variant_id"], item["quantity"], item["price"], item["total"]))

#         # ✅ Insert Payment
#         payment_status = "Completed" if transaction_id else "Pending"
#         insert_payment_query = """
#             INSERT INTO payments (order_id, customer_id, amount, payment_method, transaction_id, status)
#             VALUES (%s, %s, %s, %s, %s, %s)
#         """
#         cur.execute(insert_payment_query, (order_id, customer_id, total_price, payment_method, transaction_id, payment_status))

#         # ✅ Insert notification for Admin
#         admin_id = 14  # Replace with actual admin user ID if dynamic
#         admin_message = f"New order received. Order ID: {order_id}, Customer: {customer_name}."
#         insert_admin_notification_query = """
#             INSERT INTO notifications (user_id, title, message, is_read, created_at)
#             VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
#         """
#         cur.execute(insert_admin_notification_query, (admin_id, "New Order", admin_message, 0))

#         # ✅ Insert notification for Customer
#         customer_message = f"Your order has been placed successfully. Order ID: {order_id}."
#         insert_customer_notification_query = """
#             INSERT INTO notifications (user_id, title, message, is_read, created_at)
#             VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
#         """
#         cur.execute(insert_customer_notification_query, (user_id, "Order Confirmation", customer_message, 0))

#         mysql.connection.commit()
#         cur.close()

#         return jsonify({"message": "Order placed successfully", "order_id": order_id, "payment_status": payment_status}), 201

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500



@app.route('/api/orders', methods=['POST']) 
@token_required
def place_order():
    try:
        data = request.json
        total_price = data.get("total_price")
        order_items = data.get("items")
        payment_method = data.get("payment_method")
        transaction_id = data.get("transaction_id")
        delivery_boy_id = data.get("delivery_boy_id")  # ✅ new field from frontend

        if not total_price or not order_items or not payment_method:
            return jsonify({"error": "Missing required fields"}), 400

        user_id = g.user["user_id"]  # from token
        customer_id = g.user["customer_id"]
        customer_name = g.user["customer_name"]

        assign_status = "assigned" if delivery_boy_id else "not_assigned"

        cur = mysql.connection.cursor()

        # ✅ Insert into orders table
        insert_order_query = """
            INSERT INTO orders (customer_id, total_price, status, delivery_boy_id, assign)
            VALUES (%s, %s, %s, %s, %s)
        """
        cur.execute(insert_order_query, (customer_id, total_price, "Pending", delivery_boy_id, assign_status))
        order_id = cur.lastrowid

        # ✅ Insert order items
        insert_order_item_query = """
            INSERT INTO order_items (order_id, variant_id, quantity, price, total)
            VALUES (%s, %s, %s, %s, %s)
        """
        for item in order_items:
            cur.execute(insert_order_item_query,
                        (order_id, item["variant_id"], item["quantity"], item["price"], item["total"]))

        # ✅ Insert payment
        payment_status = "Completed" if transaction_id else "Pending"
        insert_payment_query = """
            INSERT INTO payments (order_id, customer_id, amount, payment_method, transaction_id, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cur.execute(insert_payment_query, (order_id, customer_id, total_price, payment_method, transaction_id, payment_status))

        # ✅ Insert admin notification
        admin_id = 14  # static admin ID
        admin_message = f"New order received. Order ID: {order_id}, Customer: {customer_name}."
        insert_admin_notification_query = """
            INSERT INTO notifications (user_id, title, message, is_read, created_at)
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
        """
        cur.execute(insert_admin_notification_query, (admin_id, "New Order", admin_message, 0))

        # ✅ Insert customer notification
        customer_message = f"Your order has been placed successfully. Order ID: {order_id}."
        insert_customer_notification_query = """
            INSERT INTO notifications (user_id, title, message, is_read, created_at)
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
        """
        cur.execute(insert_customer_notification_query, (user_id, "Order Confirmation", customer_message, 0))

        mysql.connection.commit()
        cur.close()

        return jsonify({
            "message": "Order placed successfully",
            "order_id": order_id,
            "payment_status": payment_status
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500





# @app.route('/api/book-an-orders', methods=['GET'])
# def bookorders():
#     try:
#         cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

#         # ✅ Fetch filter parameters (optional)
#         start_date = request.args.get('from')
#         end_date = request.args.get('to')

#         # ✅ Base query for fetching orders
#         query = """
#             SELECT
#                 o.order_id, o.order_date, o.total_price, o.status,
#                 c.customer_id, c.name AS customer_name
#             FROM orders o
#             JOIN customers c ON o.customer_id = c.customer_id
#         """
        
#         query_conditions = []
#         query_params = []

#         # ✅ Apply date filter if provided
#         if start_date and end_date:
#             query_conditions.append("o.order_date BETWEEN %s AND %s")
#             query_params.extend([start_date, end_date])

#         if query_conditions:
#             query += " WHERE " + " AND ".join(query_conditions)

#         query += " ORDER BY o.order_id DESC"

#         cursor.execute(query, query_params)
#         orders_data = cursor.fetchall()

#         if not orders_data:
#             return jsonify([]), 200  # Return empty list if no orders found

#         # ✅ Fetch order items with product details
#         order_ids = tuple(order["order_id"] for order in orders_data)
#         if not order_ids:
#             return jsonify(orders_data), 200  # No orders found

#         query_placeholders = ', '.join(['%s'] * len(order_ids))
#         cursor.execute(f"""
#             SELECT
#                 oi.order_item_id, oi.order_id, oi.quantity, oi.price AS item_price, oi.total AS item_total,
#                 p.product_id, p.product_name, p.description,
#                 ps.weight, ps.stock AS stock_quantity, ps.price AS variant_price
#             FROM order_items oi
#             JOIN product_stock ps ON oi.variant_id = ps.id
#             JOIN products p ON ps.product_id = p.product_id
#             WHERE oi.order_id IN ({query_placeholders})
#         """, order_ids)
#         order_items_data = cursor.fetchall()

#         # ✅ Fetch product images
#         cursor.execute("SELECT product_id, image_url FROM product_images")
#         images_data = cursor.fetchall()
#         cursor.close()

#         # ✅ Base URL for images (adjust as needed)
#         base_url = "http://127.0.0.1:5000/static/uploads/"

#         # ✅ Convert fetched data into dictionaries
#         orders = {row["order_id"]: {
#             "order_id": row["order_id"],
#             "order_date": row["order_date"],
#             "total_price": row["total_price"],
#             "status": row["status"],
#             "customer": {
#                 "customer_id": row["customer_id"],
#                 "name": row["customer_name"]
#             },
#             "items": []
#         } for row in orders_data}

#         # ✅ Create a dictionary for product images
#         product_images = {}
#         for img in images_data:
#             product_id = img["product_id"]
#             if product_id not in product_images:
#                 product_images[product_id] = []
#             if img["image_url"]:
#                 product_images[product_id].append(f"{base_url}{img['image_url']}")

#         # ✅ Process order items and attach images
#         for item in order_items_data:
#             order_id = item["order_id"]
#             product_id = item["product_id"]
#             order_item = {
#                 "order_item_id": item["order_item_id"],
#                 "product_id": product_id,
#                 "product_name": item["product_name"],
#                 "description": item["description"],
#                 "quantity": item["quantity"],
#                 "item_price": float(item["item_price"]),
#                 "item_total": float(item["item_total"]),
#                 "variant": {
#                     "weight": item["weight"],
#                     "stock_quantity": item["stock_quantity"],
#                     "price": float(item["variant_price"])
#                 },
#                 "images": product_images.get(product_id, [])  # Attach images from product_images dict
#             }
#             orders[order_id]["items"].append(order_item)

#         return jsonify(list(orders.values())), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


@app.route('/api/book-a-orders', methods=['GET'])
def bookorders():
    print("abcd")
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # ✅ Fetch filter parameters (optional)
        start_date = request.args.get('fromDate')
        end_date = request.args.get('toDate')

        print(start_date,end_date)

        # ✅ Base query for fetching orders
        query = """
            SELECT
                o.order_id, o.order_date, o.total_price, o.status,
                c.customer_id, c.name AS customer_name,c.phone AS customer_contact
            FROM orders o
            JOIN customers c ON o.customer_id = c.customer_id
        """
        
        query_conditions = []
        query_params = []

        # ✅ Apply date filter if both dates are provided
        if start_date and end_date:
            query_conditions.append("DATE(o.order_date) BETWEEN %s AND %s")
            query_params.extend([start_date, end_date])

        elif start_date:
            query_conditions.append("DATE(o.order_date) >= %s")
            query_params.append(start_date)

        elif end_date:
            query_conditions.append("DATE(o.order_date) <= %s")
            query_params.append(end_date)

        if query_conditions:
            query += " WHERE " + " AND ".join(query_conditions)

        query += " ORDER BY o.order_id DESC"

        cursor.execute(query, query_params)
        orders_data = cursor.fetchall()

        if not orders_data:
            return jsonify([]), 200  # Return empty list if no orders found

        return jsonify(orders_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


#admin login

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.json
        phone = data.get('phone')
        password = data.get('password')

        if not phone or not password:
            return jsonify({"error": "Phone and password are required"}), 400

        conn = mysql.connection
        cursor = conn.cursor()

        # Fetch admin user by phone number
        cursor.execute("SELECT user_id, name, phone, password, role FROM users WHERE phone = %s AND role = 'admin'", (phone,))
        user = cursor.fetchone()

        if user:
            user_id, name, phone, stored_password, role = user

            # ✅ Plain text password comparison (⚠ Not Secure for Production)
            if stored_password == password:

                # Generate JWT Token (Valid for 1 hour)
                token_payload = {
                    "user_id": user_id,
                    "name": name,
                    "phone": phone,
                    "role": role,
                    "exp": datetime.utcnow() + timedelta(hours=1)
                }
                token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

                return jsonify({
                    "message": "Admin login successful",
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
            return jsonify({"error": "Admin user not found"}), 404

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

    cursor.execute("""
        SELECT c.name, c.email,c.phone, c.profile_picture, a.address, a.city, a.state, a.zip_code
        FROM customers c
        LEFT JOIN addresses a ON c.customer_id = a.customer_id
        WHERE c.customer_id = %s
    """, (customer_id,))
    
    customer = cursor.fetchone()

    if not customer:
        return jsonify({"error": "Customer not found"}), 404

    print(customer)

    name, email,phone, profile_picture, address, city, state, zip_code = customer

    return jsonify({
        "customer_id": customer_id,
        "customer_name": name,
        "email": email,
        "phone": phone,
        "profile_picture": profile_picture,
        "address": {
            "street": address,
            "city": city,
            "state": state,
            "zip_code": zip_code
        }
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
        category_name = request.form.get("name")
        image = request.files.get("image")

        if not category_name:
            return jsonify({"error": "Category name is required"}), 400

        cursor = mysql.connection.cursor()

        # Fetch existing category
        cursor.execute("SELECT image FROM categories WHERE category_id = %s", (category_id,))
        existing_category = cursor.fetchone()

        if not existing_category:
            return jsonify({"message": "Category not found"}), 404

        image_filename = existing_category[0]  # Default to existing image

        # Handle image upload if a new image is provided
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_filename = filename

        # Update category details in the database
        cursor.execute("UPDATE categories SET category_name = %s, image = %s WHERE category_id = %s",
                       (category_name, image_filename, category_id))
        mysql.connection.commit()

        cursor.close()
        return jsonify({"message": "Category updated successfully"}), 200

    except Exception as e:
        print(f"Database Error: {e}")  # Log error for debugging
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




@app.route('/api/categories/<int:category_id>', methods=['GET'])
def get_category_by_id(category_id):
    try:
        cursor = mysql.connection.cursor()

        # ✅ Fetch the category by ID
        query = "SELECT * FROM categories WHERE category_id = %s"
        cursor.execute(query, (category_id,))
        category = cursor.fetchone()

        # ✅ Check if category exists
        if not category:
            return jsonify({"message": "Category not found"}), 404

        # ✅ Get column names
        column_names = [desc[0] for desc in cursor.description]
        base_url = "http://127.0.0.1:5000/static/uploads/"  # Change to your actual base URL

        # ✅ Convert result to dictionary
        category_data = dict(zip(column_names, category))

        # ✅ Convert image name to URL if it exists
        if "image" in category_data and category_data["image"]:
            category_data["image"] = f"{base_url}{category_data['image']}"

        cursor.close()
        return jsonify({"data": category_data}), 200

    except Exception as e:
        print(f"Database Error: {e}")  # ✅ Log error for debugging
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

# Get Order by ID with Order Items
@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Fetch order details along with the customer and delivery boy name
        cursor.execute("""
            SELECT 
                o.*, 
                c.name AS customer_name, 
                c.email,
                c.phone,
                db.name AS delivery_boy_name
            FROM orders o 
            JOIN customers c ON o.customer_id = c.customer_id
            LEFT JOIN delivery_boys db ON o.delivery_boy_id = db.delivery_boy_id
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


# 📌 Add Product using category_name instead of category_id
@app.route('/api/products', methods=['POST'])
def add_product():
    data = request.json
    category_name = data.get('category_name')  # Get category_name instead of category_id
    product_name = data.get('product_name')
    description = data.get('description', '')
    added_by = data.get('added_by')

    if not category_name or not product_name or not added_by:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        cur = mysql.connection.cursor()

        # Get category_id from category_name
        cur.execute("SELECT category_id FROM categories WHERE category_name = %s", (category_name,))
        category = cur.fetchone()

        if not category:
            return jsonify({"error": "Category not found"}), 404

        category_id = category[0]  # Extract category_id

        # Insert product using category_id
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
                    products[product_id]["defaultWeightId"] = stock["id"]

        return jsonify(list(products.values())), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/api/best_selling_products', methods=['GET'])
def best_selling_products():
    try:
        cur = mysql.connection.cursor()

        # ✅ Fetch best-selling products using quantity sold
        cur.execute("""
            SELECT 
                p.product_id, 
                p.product_name, 
                SUM(oi.quantity) AS total_sales,
                (SELECT image_url FROM product_images pi WHERE pi.product_id = p.product_id LIMIT 1) AS image_url
            FROM products p
            JOIN product_stock ps ON p.product_id = ps.product_id
            JOIN order_items oi ON ps.id = oi.variant_id
            GROUP BY p.product_id, p.product_name
            ORDER BY total_sales DESC
            LIMIT 10
        """)

        best_sellers = cur.fetchall()
        cur.close()

        # Convert results to JSON format
        columns = ["product_id", "product_name", "total_sales", "image_url"]
        best_sellers_data = [dict(zip(columns, row)) for row in best_sellers]

        return jsonify(best_sellers_data), 200

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
    category_name = data.get('category_name')
    product_name = data.get('product_name')
    description = data.get('description', '')
    added_by = data.get('added_by')

    if not category_name or not product_name or not added_by:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        cur = mysql.connection.cursor()

        # Fetch category_id using category_name
        cur.execute("SELECT category_id FROM categories WHERE category_name = %s", (category_name,))
        category = cur.fetchone()

        if not category:
            return jsonify({"error": "Category not found"}), 404

        category_id = category[0]  # Extract category_id from the query result

        # Update product details in the products table
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





# # ✅ Add a Variant (Ensures product_id Exists)
# @app.route('/api/variants', methods=['POST'])
# def add_variant():
#     data = request.json
#     product_id = data.get('product_id')
#     weight = data.get('weight')
#     price = data.get('price')
#     available_stock = data.get('available_stock')

#     if not product_id or weight is None or price is None or available_stock is None:
#         return jsonify({"error": "Missing required fields"}), 400

#     try:
#         cur = mysql.connection.cursor()
        
#         # 🔹 Check if product_id exists
#         cur.execute("SELECT COUNT(*) FROM products WHERE product_id = %s", (product_id,))
#         result = cur.fetchone()
#         if result[0] == 0:
#             return jsonify({"error": "Invalid product_id"}), 400

#         # 🔹 Insert Variant Data
#         cur.execute(
#             "INSERT INTO product_variants (product_id, weight, price, available_stock) VALUES (%s, %s, %s, %s)",
#             (product_id, weight, price, available_stock)
#         )
#         mysql.connection.commit()
#         variant_id = cur.lastrowid
#         cur.close()

#         return jsonify({"message": "Variant added successfully", "variant_id": variant_id}), 201
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500




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


@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications():
    try:
        user_id = g.user["user_id"]  # Extract user ID from token
        cur = mysql.connection.cursor(cursorclass=MySQLdb.cursors.DictCursor)  # Use DictCursor
 
        # ✅ Fetch notifications for the logged-in user, ordered by latest
        fetch_notifications_query = """
            SELECT id, title, message, is_read, created_at
            FROM notifications
            WHERE user_id = %s
            ORDER BY created_at DESC
        """
        cur.execute(fetch_notifications_query, (user_id,))
        notifications = cur.fetchall()  # Returns list of dictionaries
 
        cur.close()
        return jsonify({"notifications": notifications}), 200  # Returns data with column names
 
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.route('/api/notifications/mark-read/<int:notification_id>', methods=['POST'])
@token_required
def mark_notification_as_read(notification_id):
    try:
        user_id = g.user["user_id"]  # Extract user ID from token
        cur = mysql.connection.cursor()
 
        # ✅ Check if the notification exists for the user
        check_query = "SELECT id FROM notifications WHERE id = %s AND user_id = %s"
        cur.execute(check_query, (notification_id, user_id))
        notification = cur.fetchone()
 
        if not notification:
            cur.close()
            return jsonify({"error": "Notification not found"}), 404
 
        # ✅ Update the notification to mark as read
        update_query = "UPDATE notifications SET is_read = TRUE WHERE id = %s"
        cur.execute(update_query, (notification_id,))
        mysql.connection.commit()
        cur.close()
 
        return jsonify({"message": "Notification marked as read", "id": notification_id}), 200
 
    except Exception as e:
        return jsonify({"error": str(e)}), 500







# Create Delivery Boy
@app.route('/api/delivery_boys', methods=['POST'])
def create_delivery_boy():
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        phone = data.get('phone')
        address = data.get('address')
        password = data.get('password')  # You should hash this in production

        # Validate required fields
        if not all([name, email, phone, address, password]):
            return jsonify({"success": False, "message": "All fields are required"}), 400

        cursor = mysql.connection.cursor()

        # Optional: Check if email already exists
        cursor.execute("SELECT * FROM delivery_boys WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            cursor.close()
            return jsonify({"success": False, "message": "Email already registered"}), 409

        # Insert new delivery agent
        cursor.execute("""
            INSERT INTO delivery_boys (name, email, phone, address, password)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, email, phone, address, password))  # Hash the password ideally

        mysql.connection.commit()
        cursor.close()

        return jsonify({"success": True, "message": "Delivery agent registered successfully"}), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# Get All Delivery Boys
@app.route('/api/delivery_boys', methods=['GET'])
def get_delivery_boys():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM delivery_boys")
        results = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        delivery_boys = [dict(zip(column_names, row)) for row in results]
        cursor.close()
        return jsonify({"delivery_boys": delivery_boys}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/orders/<int:order_id>/assign", methods=["PUT"])
def assign_delivery_boy(order_id):
    data = request.json
    delivery_boy_id = data.get("delivery_boy_id")

    if not delivery_boy_id:
        return jsonify({"error": "Missing delivery boy ID"}), 400

    # Example query - adjust for your DB setup
    cur = mysql.connection.cursor()
    cur.execute("UPDATE orders SET delivery_boy_id=%s, assign='assigned' WHERE order_id=%s", 
                (delivery_boy_id, order_id))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Delivery boy assigned successfully."})






# Update Delivery Boy
@app.route('/api/delivery_boys/<int:id>', methods=['PUT'])
def update_delivery_boy(id):
    try:
        name = request.json.get('name')
        phone = request.json.get('phone')
        is_active = request.json.get('is_active')

        cursor = mysql.connection.cursor()
        cursor.execute("""
            UPDATE delivery_boys 
            SET name = %s, phone = %s, is_active = %s 
            WHERE delivery_boy_id = %s
        """, (name, phone, is_active, id))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Delivery boy updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/delivery_boy_login', methods=['POST'])
def delivery_boy_login():
    try:
        data = request.get_json()
        phone = data.get('phone')
        password = data.get('password')

        if not phone or not password:
            return jsonify({"success": False, "message": "Phone and password are required"}), 400

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM delivery_boys WHERE phone = %s", (phone,))
        row = cursor.fetchone()
        columns = [col[0] for col in cursor.description]
        cursor.close()

        user = dict(zip(columns, row)) if row else None

        if user:
            if user['password'] == password:
                # Generate JWT token using app.config['SECRET_KEY']
                token_payload = {
                    'delivery_boy_id': user['delivery_boy_id'],
                    'name': user['name'],
                    'exp': datetime.utcnow() + timedelta(days=1)  # token valid for 1 day
                }
                token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')

                return jsonify({
                    "success": True,
                    "message": "Login successful",
                    "token": token,
                    "delivery_boy_id": user['delivery_boy_id'],
                    "name": user['name']
                }), 200
            else:
                return jsonify({"success": False, "message": "Incorrect password"}), 401
        else:
            return jsonify({"success": False, "message": "Delivery boy not found"}), 404

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# Delete Delivery Boy
@app.route('/api/delivery_boys/<int:id>', methods=['DELETE'])
def delete_delivery_boy(id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM delivery_boys WHERE delivery_boy_id = %s", (id,))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Delivery boy deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500







# Create OTP for Order
@app.route('/api/order_otps', methods=['POST'])
def create_order_otp():
    try:
        order_id = request.json.get('order_id')
        otp_code = request.json.get('otp_code')  # Should be generated randomly ideally
        expires_in_minutes = request.json.get('expires_in', 5)

        expires_at = datetime.now() + timedelta(minutes=expires_in_minutes)

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO order_otps (order_id, otp_code, expires_at)
            VALUES (%s, %s, %s)
        """, (order_id, otp_code, expires_at))
        mysql.connection.commit()
        cursor.close()
        return jsonify({"message": "OTP created"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Get All OTPs
@app.route('/api/order_otps', methods=['GET'])
def get_order_otps():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM order_otps")
        results = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        otps = [dict(zip(column_names, row)) for row in results]
        cursor.close()
        return jsonify({"order_otps": otps}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Update OTP (e.g., mark as used)
@app.route('/api/order_otps/<int:id>', methods=['PUT'])
def update_order_otp(id):
    try:
        is_used = request.json.get('is_used', True)

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE order_otps SET is_used = %s WHERE otp_id = %s", (is_used, id))
        mysql.connection.commit()
        cursor.close()
        return jsonify({"message": "OTP updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Delete OTP
@app.route('/api/order_otps/<int:id>', methods=['DELETE'])
def delete_order_otp(id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM order_otps WHERE otp_id = %s", (id,))
        mysql.connection.commit()
        cursor.close()
        return jsonify({"message": "OTP deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/delivery_dashboard', methods=['GET'])
@token_required
def delivery_dashboard():
    try:
        delivery_boy_id = g.user['delivery_boy_id']

        cursor = mysql.connection.cursor()

        # Get delivery agent's name
        cursor.execute("SELECT name FROM delivery_boys WHERE delivery_boy_id = %s", (delivery_boy_id,))
        result = cursor.fetchone()
        agent_name = result[0] if result else "Delivery Agent"

        # Count assigned orders (not delivered)
        cursor.execute("""
            SELECT COUNT(*) 
            FROM orders 
            WHERE delivery_boy_id = %s AND status != 'Delivered'
        """, (delivery_boy_id,))
        assigned_count = cursor.fetchone()[0]

        # Count delivered orders
        cursor.execute("""
            SELECT COUNT(*) 
            FROM orders 
            WHERE delivery_boy_id = %s AND status = 'Delivered'
        """, (delivery_boy_id,))
        delivered_count = cursor.fetchone()[0]

        # Fetch assigned orders details
        cursor.execute("""
            SELECT 
                o.order_id,
                o.total_price,
                o.status,
                o.order_date,
                o.assign,
                c.name AS customer_name,
                c.phone AS customer_phone,
                c.email AS customer_email
            FROM orders o
            JOIN customers c ON o.customer_id = c.customer_id
            WHERE o.delivery_boy_id = %s AND o.status != 'Delivered'
            ORDER BY o.order_date DESC
        """, (delivery_boy_id,))
        assigned_rows = cursor.fetchall()
        assigned_columns = [desc[0] for desc in cursor.description]
        assigned_orders_list = [dict(zip(assigned_columns, row)) for row in assigned_rows]

        # Fetch delivered orders details
        cursor.execute("""
            SELECT 
                o.order_id,
                o.total_price,
                o.status,
                o.order_date,
                o.assign,
                c.name AS customer_name,
                c.phone AS customer_phone,
                c.email AS customer_email
            FROM orders o
            JOIN customers c ON o.customer_id = c.customer_id
            WHERE o.delivery_boy_id = %s AND o.status = 'Delivered'
            ORDER BY o.order_date DESC
        """, (delivery_boy_id,))
        delivered_rows = cursor.fetchall()
        delivered_columns = [desc[0] for desc in cursor.description]
        delivered_orders_list = [dict(zip(delivered_columns, row)) for row in delivered_rows]

        cursor.close()

        return jsonify({
            'success': True,
            'name': agent_name,
            'assigned_orders': assigned_count,
            'delivered_orders': delivered_count,
            'assigned_orders_list': assigned_orders_list,
            'delivered_orders_list': delivered_orders_list
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/delivery_orders', methods=['GET'])
@token_required
def delivery_orders():
    try:
        delivery_boy_id = g.user['delivery_boy_id']

        cursor = mysql.connection.cursor()

        query = """
            SELECT 
                o.order_id,
                o.total_price,
                o.status,
                o.order_date,
                o.assign,
                c.name AS customer_name,
                c.phone AS customer_phone,
                c.email AS customer_email
            FROM orders o
            JOIN customers c ON o.customer_id = c.customer_id
            WHERE o.delivery_boy_id = %s
            ORDER BY o.order_date DESC
        """
        cursor.execute(query, (delivery_boy_id,))
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        cursor.close()

        orders = [dict(zip(columns, row)) for row in rows]

        return jsonify({
            "success": True,
            "orders": orders
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route('/api/order_details/<int:order_id>', methods=['GET'])
@token_required
def order_details(order_id):
    try:
        delivery_boy_id = g.user['delivery_boy_id']
        cursor = mysql.connection.cursor()

        # Check if the order belongs to the delivery boy
        order_query = """
            SELECT 
                o.order_id,
                o.total_price,
                o.status,
                o.order_date,
                o.assign,
                c.name AS customer_name,
                c.phone AS customer_phone,
                c.email AS customer_email
            FROM orders o
            JOIN customers c ON o.customer_id = c.customer_id
            WHERE o.order_id = %s AND o.delivery_boy_id = %s
        """
        cursor.execute(order_query, (order_id, delivery_boy_id))
        order_row = cursor.fetchone()

        if not order_row:
            return jsonify({
                "success": False,
                "message": "Order not found or unauthorized access."
            }), 404

        order_columns = [desc[0] for desc in cursor.description]
        order_data = dict(zip(order_columns, order_row))

        # Fetch items in the order
        items_query = """
            SELECT 
                oi.variant_id,
                oi.quantity,
                oi.price,
                (oi.quantity * oi.price) AS total
            FROM order_items oi
            WHERE oi.order_id = %s
        """
        cursor.execute(items_query, (order_id,))
        items_rows = cursor.fetchall()
        items_columns = [desc[0] for desc in cursor.description]
        items = [dict(zip(items_columns, row)) for row in items_rows]

        cursor.close()

        return jsonify({
            "success": True,
            "order": order_data,
            "items": items
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500



if __name__ == '__main__':
    app.run(debug=True)





