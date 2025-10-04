from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

uri = os.getenv("MONGO_CONN")
db_name = os.getenv("DB_NAME")
coll_name = os.getenv("COLLECTION")

client = MongoClient(uri)
db = client[db_name]
collection = db[coll_name]
active_user = db["active_user"]
products = db["products"]

carts = db["carts"]


