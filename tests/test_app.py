# tests/test_app.py

import json
import pytest
from typing import Any, Dict
from unittest.mock import patch, MagicMock
from app import app

@pytest.fixture
def client() -> Any:
    """Create and yield a test client for the Flask app."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

# ----- Tests for /generate -----

@patch("services.leaks.check_leaks", return_value=False)
@patch("models.database.execute_query")
@patch("services.policy.generate_password", return_value="TestPassword123")
@patch("services.auth.jwt_gen", return_value="fake_jwt_token")
def test_generate_valid(
    mock_jwt_gen: Any,
    mock_generate_password: Any,
    mock_execute_query: Any,
    mock_check_leaks: Any,
    client: Any,
) -> None:
    """
    Test that a valid POST request to /generate returns a JSON response containing
    a generated password and JWT token.
    """
    payload: Dict[str, Any] = {"username": "testuser"}
    response = client.post("/generate", json=payload)
    data: Dict[str, Any] = response.get_json()
    assert response.status_code == 200
    assert "generated_password" in data
    assert "token" in data
    assert data["generated_password"] == "TestPassword123"
    assert data["token"] == "fake_jwt_token"
    assert mock_execute_query.called

def test_generate_missing_username(client: Any) -> None:
    """
    Test that /generate returns 400 when the JSON payload is missing the username.
    """
    response = client.post("/generate", json={})
    data: Dict[str, Any] = response.get_json()
    assert response.status_code == 400
    assert "error" in data

def test_generate_no_json(client: Any) -> None:
    """
    Test that /generate returns 400 when no JSON body is provided.
    """
    response = client.post("/generate")
    data: Dict[str, Any] = response.get_json()
    assert response.status_code == 400
    assert "error" in data

# ----- Tests for /retrieve -----

@patch("models.database.execute_query")
@patch("services.auth.decode_jwt")
@patch("services.auth.jwt_gen", return_value="new_fake_jwt_token")
@patch("services.auth.generate_uid_hash", return_value="hashed_testuser")
def test_retrieve_valid(
    mock_generate_uid_hash: Any,
    mock_jwt_gen: Any,
    mock_decode_jwt: Any,
    mock_execute_query: Any,
    client: Any,
) -> None:
    """
    Test that a valid GET request to /retrieve returns a new JWT token.
    """
    # Simulate the database returning that a user with the given username exists
    mock_execute_query.return_value = [(1,)]
    # Simulate a valid JWT
    mock_decode_jwt.return_value = {
        "sub": "hashed_testuser",
        "ist": "2025-01-20T10:00:00",
        "exp": "9999-01-01T00:00:00"
    }
    response = client.get(
        "/retrieve?username=testuser",
        headers={"Authorization": "valid_jwt_token"}
    )
    data: Dict[str, Any] = response.get_json()
    assert response.status_code == 200
    assert "new_token" in data
    assert data["new_token"] == "new_fake_jwt_token"

@patch("models.database.execute_query")
@patch("services.auth.decode_jwt", side_effect=Exception("Invalid token"))
@patch("services.auth.generate_uid_hash", return_value="hashed_testuser")
def test_retrieve_invalid_token(
    mock_generate_uid_hash: Any,
    mock_decode_jwt: Any,
    mock_execute_query: Any,
    client: Any,
) -> None:
    """
    Test that /retrieve returns 401 when an invalid JWT token is provided.
    """
    mock_execute_query.return_value = [(1,)]
    response = client.get(
        "/retrieve?username=testuser",
        headers={"Authorization": "invalid_jwt_token"}
    )
    data: Dict[str, Any] = response.get_json()
    assert response.status_code == 401
    assert "error" in data

def test_retrieve_no_token(client: Any) -> None:
    """
    Test that /retrieve returns 400 when the Authorization header is missing.
    """
    response = client.get("/retrieve?username=testuser")
    data: Dict[str, Any] = response.get_json()
    assert response.status_code == 400
    assert "error" in data

def test_retrieve_no_username(client: Any) -> None:
    """
    Test that /retrieve returns 400 when the username query parameter is missing.
    """
    response = client.get(
        "/retrieve",
        headers={"Authorization": "valid_jwt_token"}
    )
    data: Dict[str, Any] = response.get_json()
    assert response.status_code == 400
    assert "error" in data
