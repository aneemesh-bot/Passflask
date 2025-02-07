# tests/test_auth.py

import hashlib
import jwt
from datetime import datetime, timedelta
from typing import Any, Dict
import pytest
from services.auth import generate_uid_hash, generate_db_key, jwt_gen, decode_jwt
from config import JWT_SECRET

def test_generate_uid_hash() -> None:
    username: str = "testuser"
    uid_hash: str = generate_uid_hash(username)
    expected: str = hashlib.sha256(username.encode()).hexdigest()
    assert uid_hash == expected

def test_generate_db_key() -> None:
    username: str = "testuser"
    password: str = "password123"
    db_key: str = generate_db_key(username, password)
    expected: str = hashlib.sha256((username + password).encode()).hexdigest()
    assert db_key == expected

def test_jwt_gen_and_decode() -> None:
    username: str = "testuser"
    token: str = jwt_gen(username)
    payload: Dict[str, Any] = decode_jwt(token)
    uid_hash: str = generate_uid_hash(username)
    # Does subject match the hashed uid?
    assert payload["sub"] == uid_hash
    # Expiration time check with timezone-aware object
    exp = datetime.fromisoformat(payload["exp"])
    now = datetime.now(timezone.utc)
    diff = exp - now
    assert diff > timedelta(hours=23)

def test_invalid_jwt() -> None:
    invalid_token: str = "not_a_real_token"
    with pytest.raises(jwt.InvalidTokenError):
        decode_jwt(invalid_token)
