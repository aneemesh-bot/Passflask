# services/auth.py

import jwt
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any
from config import JWT_SECRET

def generate_uid_hash(username: str) -> str:
    """
    Generate the SHA256 hash of the username.
    
    Args:
        username: The username as a string.
    
    Returns:
        A SHA256 hash string.
    """
    return hashlib.sha256(username.encode()).hexdigest()

def generate_db_key(username: str, password: str) -> str:
    """
    Generate the database key as the SHA256 hash of the concatenated username and password.
    
    Args:
        username: The username as a string.
        password: The password as a string.
    
    Returns:
        A SHA256 hash string of (username + password).
    """
    return hashlib.sha256((username + password).encode()).hexdigest()

def jwt_gen(username: str) -> str:
    """
    Generate a JWT token with the specified username.
    
    The payload includes:
      - sub: the SHA256 hash of the username,
      - ist: the current UTC time in ISO format,
      - exp: the expiration time (24 hours from now) in ISO format.
    
    Args:
        username: The username for which to generate the token.
    
    Returns:
        A JWT token as a string.
    """
    payload: Dict[str, Any] = {
        "sub": generate_uid_hash(username),
        "ist": datetime.utcnow().isoformat(),
        "exp": (datetime.utcnow() + timedelta(hours=24)).isoformat()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_jwt(token: str) -> Dict[str, Any]:
    """
    Decode a JWT token and validate its signature and payload.
    
    Args:
        token: The JWT token as a string.
    
    Returns:
        The decoded payload as a dictionary.
    
    Raises:
        jwt.InvalidTokenError: If the token is invalid.
    """
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
