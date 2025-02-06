import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Application configurations
JWT_SECRET = os.getenv("JWT_SECRET", "default-secret-key")
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "password_manager")
