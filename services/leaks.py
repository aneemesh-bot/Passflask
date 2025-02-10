# services/leaks.py

import hashlib
import requests
from typing import Optional

def check_leaks(password: str) -> bool:
    """
    Check if the given password has been leaked using the HaveIBeenPwned API.
    
    This function uses the k-anonymity model:
      1. Hash the password using SHA1.
      2. Use the first 5 characters of the hash to query the API.
      3. Check if the remaining hash suffix appears in the API response.
    
    Args:
        password: The password to check.
    
    Returns:
        True if the password has been found in the leaked database, False otherwise.
    
    Raises:
        Exception: If the API request fails.
    """
    # Compute the SHA1 hash and convert it to uppercase for uniformity.
    sha1pwd: str = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix: str = sha1pwd[:5]
    suffix: str = sha1pwd[5:]
    
    url: str = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    if response.status_code != 200:
        raise Exception("Error querying HaveIBeenPwned API")
    
    # The response text contains lines in the format "HASH_SUFFIX:COUNT"
    for line in response.text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[0].strip() == suffix:
            return True
    return False
