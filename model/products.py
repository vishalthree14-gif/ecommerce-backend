from pymongo import MongoClient
from dotenv import load_dotenv
import os
from bson import ObjectId
from model.database import products

load_dotenv()





def insert_product(query):
    inserted_id = products.insert_one(query);
    return inserted_id;


def get_products_data(skip, limit):
    cursor = products.find().sort('created_at', -1).skip(skip).limit(limit)
    result = []
    for p in cursor:
        p["_id"] = str(p["_id"])  # convert ObjectId to string
        result.append(p)
    return result



def get_products_count():
    return products.count_documents({})


def delete_products_id(product_id):
    return products.delete_one({"_id": ObjectId(product_id)})



def update_product(product_id, query):
    return products.update_one({"_id": ObjectId(product_id)}, {"$set": query })



def get_product_id(product_id):
    return products.find_one({"_id": ObjectId(product_id)})

