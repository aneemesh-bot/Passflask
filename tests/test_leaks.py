# tests/test_leaks.py

# tests/test_leaks.py

import hashlib
import pytest
from typing import Any
from services.leaks import check_leaks

# simulate the requests.Response object.
class DummyResponse:
    def __init__(self, text: str, status_code: int) -> None:
        self.text = text
        self.status_code = status_code

def dummy_requests_get_positive(url: str) -> DummyResponse:
    """
    Simulate a successful API response where the expected hash suffix is present.
    For testing, we assume the password is "TestPassword123" and we compute its SHA1 hash.
    """
    # SHA1 of password
    sha1pwd: str = hashlib.sha1("TestPassword123".encode("utf-8")).hexdigest().upper()
    prefix: str = sha1pwd[:5]
    suffix: str = sha1pwd[5:]
    # response text that includes a line with the matching suffix.
    response_text: str = f"{suffix}:10\nOTHERHASH:5"
    return DummyResponse(response_text, 200)

def dummy_requests_get_negative(url: str) -> DummyResponse:
    """
    Simulate a successful API response where the expected hash suffix is not present.
    """
    #dummy response that doesn't include the expected suffix.
    response_text: str = "ABCDEF1234567890ABCDEF1234567890ABC:10\nOTHERHASH:5"
    return DummyResponse(response_text, 200)

def dummy_requests_get_error(url: str) -> DummyResponse:
    """
    Simulate an API response with an error (non-200 status code).
    """
    return DummyResponse("", 500)

def test_check_leaks_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that check_leaks returns True when the API response contains the matching hash suffix.
    """
    # requests.get call in services.leaks with the dummy positive function.
    monkeypatch.setattr("services.leaks.requests.get", dummy_requests_get_positive)
    result: bool = check_leaks("TestPassword123")
    assert result is True

def test_check_leaks_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that check_leaks returns False when the API response does not contain the matching hash suffix.
    """
    # requests.get call with  dummy negative function.
    monkeypatch.setattr("services.leaks.requests.get", dummy_requests_get_negative)
    result: bool = check_leaks("TestPassword123")
    assert result is False

def test_check_leaks_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that check_leaks raises an Exception when the API returns a non-200 status code.
    """
    # Patching requests.get to simulate API error
    monkeypatch.setattr("services.leaks.requests.get", dummy_requests_get_error)
    with pytest.raises(Exception) as exc_info:
        check_leaks("TestPassword123")
    assert "Error querying HaveIBeenPwned API" in str(exc_info.value)


'''
monkeypatch is a pytest fixture that allows you to replace functions or modules with our own
implementations. In this case, we're replacing the open function with a mock object that
simulates the file opening behavior.
'''