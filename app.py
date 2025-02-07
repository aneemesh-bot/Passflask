# app.py

from flask import Flask, request, jsonify, Response
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
import jwt

from services.policy import generate_password
from services.leaks import check_leaks
from services.auth import generate_db_key, generate_uid_hash, jwt_gen, decode_jwt
from models.database import execute_query

app = Flask(__name__)

@app.route("/generate", methods=["POST"])
def generate() -> Response:
    """
    Generate a new password and JWT token for a given username.

    Expects a JSON payload with a 'username' key.
    
    Returns:
        A JSON response containing the generated password and JWT token.
    """
    data: Optional[Dict[str, Any]] = request.get_json()
    if not data or "username" not in data:
        return jsonify({"error": "Username is required"}), 400

    username: str = data["username"]
    password: str = generate_password()

    # Password leak check with HaveIBeenPwned API
    while check_leaks(password):
        password = generate_password()

    # Database storage preparation
    db_key: str = generate_db_key(username, password)
    uid_hash: str = generate_uid_hash(username)
    # timezone-aware datetime for the generation date
    generation_date: str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    execute_query(
        "INSERT INTO users (db_key, uid_hash, generation_date) VALUES (%s, %s, %s)",
        (db_key, uid_hash, generation_date)
    )

    # JWT token generation
    token: str = jwt_gen(username)
    return jsonify({"generated_password": password, "token": token})

@app.route("/retrieve", methods=["GET"])
def retrieve() -> Response:
    """
    Retrieve a new JWT token for a given username if the supplied JWT token is valid.

    Query Parameters:
        - username (str): The username.
    Headers:
        - Authorization: The JWT token.

    Returns:
        A JSON response containing a new JWT token or an error message.
    """
    username: Optional[str] = request.args.get("username")
    token: Optional[str] = request.headers.get("Authorization")

    if not username or not token:
        return jsonify({"error": "Username and token are required"}), 400

    uid_hash: str = generate_uid_hash(username)
    
    # Check user existence
    result: Optional[List[Tuple[Any, ...]]] = execute_query(
        "SELECT COUNT(*) FROM users WHERE uid_hash = %s", (uid_hash,)
    )
    if not result or result[0][0] == 0:
        return jsonify({"error": "Invalid username"}), 404

    try:
        payload: Dict[str, Any] = decode_jwt(token)
        if payload["sub"] != uid_hash:
            return jsonify({"error": "Invalid token"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Generate new JWT token
    new_token: str = jwt_gen(username)
    return jsonify({"new_token": new_token})

if __name__ == "__main__":
    app.run(debug=True)
