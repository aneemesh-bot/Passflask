# services/leaks.py

from typing import TextIO

def check_leaks(password: str) -> bool:
    """
    Check if the given password exists in the leaked passwords file.
    
    Args:
        password: The password to check.
    
    Returns:
        True if the password is found in the file, False otherwise.
    """
    # Open file (read)
    with open("leaked_passwords.txt", "r") as file:  
        leaked_passwords = file.read().splitlines()
    return password in leaked_passwords
