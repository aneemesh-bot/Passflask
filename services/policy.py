# services/policy.py

import secrets
import string
from typing import Dict, Union, Set

# Define a type alias for our password policy settings.
PolicyType = Dict[str, Union[int, bool]]

# Password policy configuration.
PASSWORD_POLICY: PolicyType = {
    "length": 12,
    "include_uppercase": True,
    "include_lowercase": True,
    "include_digits": True,
    "include_special": False,
    "exclude_similar": True,
}

# Exclusion list
SIMILAR_CHARACTERS: Set[str] = {"O", "0", "l", "1", "I"}

def generate_password() -> str:
    """
    Generate a password based on the defined PASSWORD_POLICY using a cryptographically secure
    random choice from the allowed character pool.
    
    Returns:
        A generated password string.
    """
    char_pool: set[str] = set()

    if PASSWORD_POLICY["include_uppercase"]:
        char_pool.update(string.ascii_uppercase)
    if PASSWORD_POLICY["include_lowercase"]:
        char_pool.update(string.ascii_lowercase)
    if PASSWORD_POLICY["include_digits"]:
        char_pool.update(string.digits)
    if PASSWORD_POLICY["include_special"]:
        char_pool.update(string.punctuation)

    if PASSWORD_POLICY["exclude_similar"]:
        char_pool.difference_update(SIMILAR_CHARACTERS)

    # Set[] to list[] for hashability
    pool_list: list[str] = list(char_pool)
    return ''.join(secrets.choice(pool_list) for _ in range(PASSWORD_POLICY["length"]))
