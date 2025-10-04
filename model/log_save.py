from pymongo import MongoClient
from dotenv import load_dotenv
import os
from model.database import collection, active_user

load_dotenv()



def regsiter_user(query):
    return collection.insert_one(query)

def find_user(query):
    return collection.find_one(query)


def find_user_id(query):
    return collection.find_one(query)




def logged(query):
    return active_user.insert_one(query)


def find_refresh(query):
    return active_user.find_one({"refresh_token": query})

def delete_refresh(query):
    return active_user.delete_one({"refresh_token": query})

