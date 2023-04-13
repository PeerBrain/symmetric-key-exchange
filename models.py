from pydantic import BaseModel #pylint: disable=no-name-in-module


class KeyStore(BaseModel): # pylint: disable=too-few-public-methods
    """Class to define the User object for our application. This will get updated
    and more complex as development continues."""
    symmetric_key: str
    public_key: str
    

class UserKeyStore(BaseModel): # pylint: disable=too-few-public-methods
    """Class to define the User object for our application. This will get updated
    and more complex as development continues."""
    username: str
    user_password_hash : str
    key_store : KeyStore
    

class SymKeyRequest(BaseModel): # pylint: disable=too-few-public-
    username : str
    password : str
    friend_username : str