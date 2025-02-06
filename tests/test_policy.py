# tests/test_policy.py

import pytest
from services.policy import generate_password, PASSWORD_POLICY, SIMILAR_CHARACTERS
import string

def test_generate_password_length() -> None:
    """Verify the generated password matches the policy-defined length."""
    password: str = generate_password()
    assert len(password) == PASSWORD_POLICY["length"]

def test_generate_password_contains_allowed_chars() -> None:
    """
    Verify the generated password includes characters from the allowed sets.
    Checks uppercase, lowercase, digits, and special characters as applicable.
    """
    password: str = generate_password()
    if PASSWORD_POLICY["include_uppercase"]:
        assert any(c.isupper() for c in password)
    if PASSWORD_POLICY["include_lowercase"]:
        assert any(c.islower() for c in password)
    if PASSWORD_POLICY["include_digits"]:
        assert any(c.isdigit() for c in password)
    if PASSWORD_POLICY["include_special"]:
        special_chars: str = string.punctuation
        assert any(c in special_chars for c in password)

def test_generate_password_excludes_similar() -> None:
    """
    Verify that if the policy excludes similar characters, the generated password does not
    contain any characters from SIMILAR_CHARACTERS.
    """
    if PASSWORD_POLICY["exclude_similar"]:
        password: str = generate_password()
        for ch in password:
            assert ch not in SIMILAR_CHARACTERS
