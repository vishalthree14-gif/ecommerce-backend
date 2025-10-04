from flask import Flask, request, jsonify
from dotenv import load_dotenv
import os
from model.log_save import regsiter_user, find_user, logged, find_refresh, delete_refresh, find_user_id
from model.products import insert_product, get_products_data, get_products_count, delete_products_id, update_product
from model.carts import insert_data_cart, find_user_cart, update_cart, get_cart_data, update_cart_one
import cloudinary
import cloudinary.uploader
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt
from functools import wraps
from flask_cors import CORS
import json
import redis
from bson import ObjectId


load_dotenv()

PORT = os.getenv("PORT")

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app)

SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_KEY_TOKEN = os.getenv("REFRESH_KEY_TOKEN")

app.config["SECRET_KEY"] = SECRET_KEY

cloud_api_key = os.getenv("API_KEY_CLOUDINARY")
cloud_api_secret = os.getenv("API_SECRET_CLOUDINARY")
cloud_name = os.getenv("NAME_CLOUDINARY")


cloudinary.config(
    api_key = cloud_api_key,
    api_secret = cloud_api_secret,
    cloud_name = cloud_name,
    secure=True
)


redis_client = redis.StrictRedis(
    host="localhost", 
    port=6379, 
    db=0, 
    decode_responses=True 
)


@app.route('/register', methods=["POST"])
def register_func():
    data = request.form

    name = data.get('name')
    phone = data.get('phone')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')


    # Address fields
    street = data.get('street')
    city = data.get('city')
    zip_code = data.get('zip_code')
    country = data.get('country')

    
    if not all([name, phone, email, password, role, street, city, zip_code, country]):
        return jsonify({"error":"show all the fields"}), 401

    allowed_roles = ["admin", "editor", "user"]

    if role not in allowed_roles:
        return jsonify({"error":"role not valid"}), 409


    address = [{
        "street":street,
        "city": city,
        "zip_code": zip_code,
        "country": country
    }]


    photo = request.files.get('photo')

    if photo:
        upload_cloud = cloudinary.uploader.upload(photo)

        # print(upload_cloud)
        url = upload_cloud.get('secure_url')


        hash_pass = bcrypt.generate_password_hash(password).decode('utf-8')

        query = {
            "name":name,
            "phone":phone,
            "email":email,
            "password":hash_pass,
            "role":role,
            "img_path":url,
            "address": address,
            "status":True,
            "created_at":datetime.utcnow()
        }

        inserted_id = regsiter_user(query)

        # print(inserted_id)

        return jsonify({"message": "user registered successfully"}), 201

    return jsonify({"message": "something went wrong"}), 401


@app.route("/login", methods=["POST"])
def login_func():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"error": "fill all the fields"}), 304
    
    db_data = find_user({"email": email})

    if not db_data:
        return jsonify({"error":"user doesn't exist"}), 304
    
    hash_pass = db_data['password']

    check_pass = bcrypt.check_password_hash(hash_pass, password)

    if not check_pass:
        return jsonify({"error":"wrong email or password"}), 304


    login_token = jwt.encode({
        "email":email,
        "exp":datetime.utcnow()+timedelta(minutes=10)
    },
    SECRET_KEY,
    algorithm="HS256"
    )

    refresh_token = jwt.encode({
        "email": email,
        "exp": datetime.utcnow()+timedelta(hours=15)
    },
    REFRESH_KEY_TOKEN,
    algorithm="HS256"
    )

    query={
        "email":email,
        "refresh_token": refresh_token,
        "expiry_time": datetime.utcnow()+timedelta(hours=15),
        "create_at":datetime.utcnow()
    }

    db_log = logged(query)
    # print(db_log)

    return jsonify({"message":"login successfull", "token":login_token, "refresh_token": refresh_token}), 200


@app.route('/refreshToken', methods=["POST"])
def refresh_func():
    
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error":"token not found"}), 404
    
    refresh_token = auth_header.split(" ")[1]  # get the actual token
    # print("-----------", refresh_token)

    find = find_refresh(refresh_token)
    # print(find)

    if find:
        try:
            token = jwt.decode(refresh_token, REFRESH_KEY_TOKEN, algorithms=["HS256"])

            email = token.get('email')

            access_token = jwt.encode({
                "email": email,
                "exp": datetime.utcnow()+timedelta(minutes=15)
            },
            SECRET_KEY,
            algorithm="HS256"
            )

            return jsonify({"message":"token gets refreshed", "access_token": access_token})

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "refresh token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid refresh token"}), 401

    return jsonify({"error":"something went wrong"}), 404


@app.route("/logout", methods=["POST"])
def logout_func():
    auth_header = request.headers.get('Authorization')

    # print("----------", data)

    if not auth_header:
        return jsonify({"error":"token not found"}), 404
    
    refresh_token = auth_header.split(" ")[1]  # get the actual token
    if not refresh_token:
        return jsonify({"error": "refresh token not found"}), 404


    db_refresh = find_refresh(refresh_token)

    if db_refresh:
        delete_refresh(refresh_token)

        return jsonify({"message": "user logout"}), 200

    return jsonify({"error":"something went wrong"}), 404


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "token missing"}), 401
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "access token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401
        return f(payload, *args, **kwargs)
    return decorated


# # GET products with pagination + optional search
# @app.route("/products", methods=["GET"])
# def get_products():
#     page = int(request.args.get('page', 1))
#     limit = int(request.args.get('limit', 10))
#     query = request.args.get('q', "").lower()

#     # cache key for all products
#     cache_key = "products:all"

#     # Try getting all products from Redis
#     cached_data = redis_client.get(cache_key)

#     if cached_data:
#         products = json.loads(cached_data)
#         cached = True
#         print('-----------giving answer from the cache')
#     else:
#         # fetch all products from DB (simulate find_fake_all)
#         products = find_fake()   # get full list
#         redis_client.setex(cache_key, 300, json.dumps(products))
#         cached = False

#     # If query provided, filter products
#     if query:
#         products = [p for p in products if query in p["name"].lower()]

#     # Apply pagination
#     start = (page - 1) * limit
#     end = start + limit
#     paginated = products[start:end]

#     return jsonify({
#         "page": page,
#         "limit": limit,
#         "total": len(products),
#         "products": paginated,
#         "cached": cached
#     })



@app.route("/addProducts", methods=["POST"])
def addProducts():
    data = request.form

    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    category = data.get('category')
    stock = data.get("stock")
    
    if not all([name, description, price, category, stock]):
        return jsonify({"message":"send complete data"}), 404
    
    photos = request.files.getlist('photos')
    img_urls = []

    if photos:
        for img in photos:
            uploads = cloudinary.uploader.upload(img)
            url = uploads.get('secure_url')
            img_urls.append(url)

        query = {
            "name": name,
            "description": description,
            "price": float(price),
            "category": category,
            "stock": int(stock),
            "img_urls":img_urls,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "status":True
        }

        insert_product(query)

        return jsonify({"message":"new product inserted"}), 201
    
    return jsonify({"error":"something went wrong"}), 409

@app.route("/getAllProducts", methods=["GET"])
@token_required
def allProducts(payload):
    
    limit = int(request.args.get('limit', 5))
    page = int(request.args.get('page', 1))

    skip = (page-1) * limit

    data = get_products_data(skip, limit)
    total_products = get_products_count()

    return jsonify({"message":"data fatch successfully", "data":data, "total products": total_products}), 200


@app.route("/deleteProduct", methods=["DELETE"])
@token_required
def delete_products(payload):
    data = request.form

    product_id = data.get('product_id')
    product = delete_products_id(product_id)

    return jsonify({"message": f"product deleted successfully {product_id}"})


@app.route("/editProduct", methods=["PUT"])
@token_required
def edit_products(payload):
    
    data = request.form

    if data:
        name = data.get('name')
        description = data.get('description')
        price = data.get('price')
        category = data.get('category')
        stock = data.get('stock')
        
        product_id = data.get('product_id')

        query = {
            "name": name,
            "description": description,
            "price": price,
            "cateogry": category,
            "stock": stock,
            "updated_at": datetime.utcnow()
        }

        updated_id = update_product(product_id, query)

        return jsonify({"message": f"products edited successfully {updated_id}"}), 200





@app.route("/getCart", methods=['POST'])
def getProducts():

    token_header = request.headers.get('Authorization')

    if not token_header:
        return jsonify({"error":"jwt token required"}), 409

    try:
        token = token_header.split(" ")[1]
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

        user_email = data.get('email')
        print(user_email)

        user_db = find_user({'email': user_email})
        print(user_db)

        user_id = user_db.get('_id')
        print("-----------------------------------",user_id)


        # data = get_cart_data(user_id) 

        cart_data = get_cart_data(user_id)
        if cart_data:
            cart_data["_id"] = str(cart_data["_id"])
            cart_data["user_id"] = str(cart_data["user_id"])
            for item in cart_data["items"]:
                item["product_id"] = str(item["product_id"])
            cart_data["created_at"] = cart_data["created_at"].isoformat()
            cart_data["updated_at"] = cart_data["updated_at"].isoformat()

        return jsonify({"cart": cart_data}), 200


    except jwt.ExpiredSignatureError:
        return jsonify({"error": "access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid access token"}), 401


@app.route("/addToCart", methods=["POST"])
def addToCarts():
    header_data = request.headers.get('Authorization')
    if not header_data:
        return jsonify({"error": "Authorization header missing"}), 401
    
    token = header_data.split(" ")[1]
    data = request.get_json()

    try:
        token_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = token_data.get('email')
        if not email:
            return jsonify({"error": "invalid token payload"}), 401

        db_data = find_user_id({"email": email})
        if not db_data:
            return jsonify({"error": "user not found"}), 404

        user_id = db_data.get('_id')


        add_product_id = data.get("product_id")
        quantity = int(data.get('quantity', 1))

        if not add_product_id:
            return jsonify({"error": "product_id required"}), 400

        existing_cart = find_user_cart({'user_id': user_id})

        if existing_cart:
            # update existing cart
            update_cart(add_product_id, quantity, existing_cart)
            return jsonify({"message": "Cart updated"}), 200

        else:
            # create new cart
            items = [{"product_id": add_product_id, "quantity": quantity}]
            query = {
                "user_id": ObjectId(user_id),
                "items": items,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            insert_data_cart(query)
            return jsonify({"message": "New cart created"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid access token"}), 401


# @app.route("/editCart", methods=["PUT"])
# def editCart():
#     pass

# @app.route("/editCart", methods=["PUT"])
# def editCart():
#     header_data = request.headers.get('Authorization')
#     if not header_data:
#         return jsonify({"error": "Authorization header missing"}), 401
    
#     token = header_data.split(" ")[1]
#     data = request.get_json()

#     try:
#         token_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
#         email = token_data.get('email')
#         if not email:
#             return jsonify({"error": "invalid token payload"}), 401

#         db_data = find_user_id({"email": email})
#         if not db_data:
#             return jsonify({"error": "user not found"}), 404

#         user_id = db_data.get('_id')

#         product_id = data.get("product_id")
#         quantity = int(data.get("quantity", 1))

#         if not product_id:
#             return jsonify({"error": "product_id required"}), 400

#         # Find user's cart
#         cart = find_user_cart({"user_id": user_id})
#         if not cart:
#             return jsonify({"error": "cart not found"}), 404

#         # Case 1: quantity = 0 → remove item from cart
#         if quantity <= 0:
#             result = update_cart_one(
#                 {"user_id": user_id},
#                 {"$pull": {"items": {"product_id": ObjectId(product_id)}},
#                  "$set": {"updated_at": datetime.utcnow()}}
#             )
#             if result.modified_count > 0:
#                 return jsonify({"message": "Item removed from cart"}), 200
#             return jsonify({"error": "Item not found in cart"}), 404

#         # Case 2: update quantity
#         result = update_cart_one(
#             {"user_id": user_id, "items.product_id": ObjectId(product_id)},
#             {"$set": {
#                 "items.$.quantity": quantity,
#                 "updated_at": datetime.utcnow()
#             }}
#         )

#         if result.modified_count > 0:
#             return jsonify({"message": "Cart updated successfully"}), 200
#         else:
#             return jsonify({"error": "Item not found in cart"}), 404

#     except jwt.ExpiredSignatureError:
#         return jsonify({"error": "access token expired"}), 401
#     except jwt.InvalidTokenError:
#         return jsonify({"error": "invalid access token"}), 401


@app.route("/editCart", methods=["PUT"])
def editCart():
    header_data = request.headers.get('Authorization')
    if not header_data:
        return jsonify({"error": "Authorization header missing"}), 401
    
    token = header_data.split(" ")[1]
    data = request.get_json()

    try:
        token_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = token_data.get('email')
        if not email:
            return jsonify({"error": "invalid token payload"}), 401

        db_data = find_user_id({"email": email})
        if not db_data:
            return jsonify({"error": "user not found"}), 404

        user_id = db_data.get('_id')

        product_id = data.get("product_id")
        quantity = int(data.get("quantity", 1))

        if not product_id:
            return jsonify({"error": "product_id required"}), 400

        # Find user's cart
        cart = find_user_cart({"user_id": user_id})
        if not cart:
            return jsonify({"error": "cart not found"}), 404

        # Case 1: quantity = 0 → remove item
        if quantity <= 0:
            result = update_cart_one(
                {"user_id": user_id},
                {
                    "$pull": {"items": {"product_id": ObjectId(product_id)}},
                    "$set": {"updated_at": datetime.utcnow()}
                }
            )
            if result.modified_count > 0:
                return jsonify({"message": "Item removed from cart"}), 200
            return jsonify({"error": "Item not found in cart"}), 404

        # Case 2: update quantity
        result = update_cart_one(
            {"user_id": user_id, "items.product_id": ObjectId(product_id)},
            {
                "$set": {
                    "items.$.quantity": quantity,
                    "updated_at": datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({"message": "Cart updated successfully"}), 200
        else:
            return jsonify({"error": "Item not found in cart"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid access token"}), 401





if __name__ == "__main__":
    app.run(port=PORT, debug=True)

