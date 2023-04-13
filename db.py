from deta import Deta
from dotenv import load_dotenv
import os
import base64
from typing import Union
import logging
import secrets
import string
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#---LOCAL IMPORTS---#
from models import UserKeyStore, KeyStore

#---LOAD ENV VARS---#
load_dotenv()

#---DB INIT---#
DETA_KEY = os.getenv("DETA_KEY")
deta = Deta(DETA_KEY)
#---#
KEYS = deta.Base("keys_db")

def get_user_key(username):
    user_key_store = KEYS.get(username)
    return user_key_store

def get_user_friend(username : str, friend_username : str):
    if friend_username in get_user_key(username)["friends"]:
        return get_user_key(username)["friends"][friend_username]
    else:
        return None
        
def wrap_sym_key(public_key:str, symmetric_key:str):
    public_key_bytes = serialization.load_pem_public_key(public_key.encode("utf-8"))
            # Encrypt the symmetric key with the client's public key
    encrypted_sym_key = public_key_bytes.encrypt(symmetric_key.encode("utf-8"),padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        ))
    encrypted_sym_key_base64 = base64.b64encode(encrypted_sym_key).decode()
    
    return encrypted_sym_key_base64 
   
def create_user_key(username:str, password_hash:str, symmetric_key:str, public_key:str)->None:
    """Function to create a new user. It takes three strings and inputs these into the new_user dictionary. The function then
    attempts to put this dictionary in the database"""

    new_user_key_object = {
        "key": username,
        "hashed_pw" : password_hash,
        "friends" : {},
        "key_store": {
                "symmetric_key" : symmetric_key,
                "public_key" : public_key
                }
            }
    try:
        return KEYS.put(new_user_key_object)
    except Exception as error_message:
        logging.exception(error_message)
        return None
    
def generate_api_access_key():
    alphabet = string.ascii_letters + string.digits
    api_key = ''.join(secrets.choice(alphabet) for i in range(32))
    return api_key

def add_friend_encrypted_key(username, friend_username, encrypted_key):
    """Function that takes a username, the username of a friend and an encrypted key. An update dictionary is created> The function 
    will then check if the friend exists, if you are not trying to add yourself or if the user in question is not already a friend. If all
    these checks are passed and attempt is made to add the friend to the friends array in the database of the User object."""
    
    update= {
        f"friends.{friend_username}":  encrypted_key
        }
    
    try:
        
        return KEYS.update(update, username), f"User {friend_username} added as a friend successfully!"
    except Exception as error_message:
        logging.exception(error_message)
        return None


add_friend_encrypted_key("admin", "tester", "testerkey")