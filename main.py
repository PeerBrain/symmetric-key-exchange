from fastapi import FastAPI, Path, Query, HTTPException, status, Depends, Request, Header
from fastapi.security import APIKeyHeader
from starlette.status import HTTP_403_FORBIDDEN, HTTP_400_BAD_REQUEST
import requests
import os
from dotenv import load_dotenv
from passlib.context import CryptContext
import bcrypt

#---LOCAL IMPORTS---#
from db import create_user_key, generate_api_access_key, get_user_key, wrap_sym_key, get_user_friend, add_friend_encrypted_key
from models import UserKeyStore, KeyStore, SymKeyRequest

#---LOAD ENV VARS---#
load_dotenv()

#---APP INIT---#
app = FastAPI()

#---APP SECURITY INIT---#
API_KEY = os.getenv("SYM_KEY_API_KEY")

pwd_context = CryptContext(schemes =["bcrypt"], deprecated="auto")

def verify_password(plain_text_pw:str, hash_pw:str)->bool:
    """Returns True if password hash matches the plain text password. Returns False otherwise."""
    return pwd_context.verify(plain_text_pw, hash_pw)

async def api_key_checker( api_key: str = Header(None)):
    API_KEY = os.getenv("SYM_KEY_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="No API key provided!",
        )
    elif api_key != API_KEY:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )

#---API KEY GEN ROUTE---#

#route the will allow a one-time api key create request and set it in the .env. Afterwards it will refuse to create any new keys
@app.get("/init_api")
async def init_api_key():
    if os.getenv("SYM_KEY_API_KEY") is None:
        new_api_key = generate_api_access_key()
        os.environ["SYM_KEY_API_KEY"] = new_api_key
        with open(".env", "a") as env_file:
            env_file.write(f"SYM_KEY_API_KEY = {new_api_key}\n")
        load_dotenv()
        return {"api-key" : f"{new_api_key}"}
    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="API key already exists!",
        )

#---PROTECTED APP ROUTES---#        
@app.get("/")
async def root_route(api_key: str = Depends(api_key_checker)):
    return {"message" : "Root API call successful!"}

@app.post("/api/v1/user_key")
async def create_user_key_store(user_key_set : UserKeyStore, api_key: str = Depends(api_key_checker)):
    
    username = user_key_set.username
    user_password_hash = user_key_set.user_password_hash
    symmetric_key = user_key_set.key_store.symmetric_key
    public_key = user_key_set.key_store.public_key
    
    
    if  create_user_key(username, user_password_hash, symmetric_key, public_key):
        return {"message" : f"UserKeyStore object stored successfully!"}
    else: 
        return{"message" : "There was a problem with storing the data!"}
    
@app.post("/api/v1/user_keys")
async def get_user_key_store(sym_key_req : SymKeyRequest, api_key: str = Depends(api_key_checker)):
    """Function will take the requesters username and password to verify if the user is actually requesting the operation. After verification it will return an encrypted
    the friends symmetric key."""
    
    username = sym_key_req.username
    password = sym_key_req.password
    friend_username = sym_key_req.friend_username
    
    user_key_store = get_user_key(username)
    
    if verify_password(password, user_key_store["hashed_pw"]):
        if not get_user_friend(username, friend_username):
            
            friend_key_store = get_user_key(friend_username)       
            
            encrypted_sym_key = wrap_sym_key(str(user_key_store["key_store"]["public_key"]), str(friend_key_store["key_store"]["symmetric_key"]))
            
            add_friend_encrypted_key(username, friend_username, encrypted_sym_key)
            return {"Friend Symmetric Key" : f"{encrypted_sym_key}"}
        else:
            return {"Friend Symmetric Key" : f"{get_user_friend(username, friend_username)}"}
    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Username/Password error! Operation only allowed if the actual user is requesting the operation.",)
        

print("test")