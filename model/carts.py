from pymongo import MongoClient
from dotenv import load_dotenv
import os
from bson import ObjectId
from datetime import datetime
from model.database import carts



def insert_data_cart(query):
    inserted_id = carts.insert_one(query);
    return inserted_id;

def find_user_cart(query):
    return carts.find_one(query)


def update_cart(product_id, quantity, exisiting_cart):

    product_found = False
    for item in exisiting_cart["items"]:
        if item['product_id'] == product_id:

            item['quantity'] += quantity
            product_found = True
            break

    if not product_found:
        exisiting_cart['items'].append({'product_id': product_id, 'quantity': quantity})


    carts.update_one(  
        {'_id': exisiting_cart["_id"]},
        {"$set":{"items": exisiting_cart['items'], "updated_at": datetime.utcnow()}}
        )


def get_cart_data(query):
   return carts.find_one({"user_id": query})



def update_cart_one(filter_query, update_query):
    return carts.update_one(filter_query, update_query)


