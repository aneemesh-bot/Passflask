# models/database.py

from typing import Any, List, Optional, Tuple
import mysql.connector
from mysql.connector import Error
from mysql.connector.connection import MySQLConnection  # Importing the connection type
from config import MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE


def get_db_connection() -> MySQLConnection:
    """
    Establish a connection to the MySQL database.
    
    Returns:
        A MySQLConnection object.
    
    Raises:
        mysql.connector.Error: If the connection fails.
    """
    try:
        conn: MySQLConnection = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            charset='utf8mb4',
            collation='utf8mb4_general_ci'
        )
        return conn
    except Error as e:
        print(f"Error connecting to the database: {e}")
        raise


def execute_query(
    query: str, params: Optional[Tuple[Any, ...]] = None
) -> Optional[List[Tuple[Any, ...]]]:
    """
    Execute a SQL query with optional parameters.
    
    Args:
        query: The SQL query string to be executed.
        params: An optional tuple of parameters for the query.
    
    Returns:
        - For SELECT queries: A list of tuples, where each tuple represents a row of results.
        - For non-SELECT queries: None.
    
    Raises:
        mysql.connector.Error: If an error occurs during query execution.
    """
    conn: MySQLConnection = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        # If the query is a SELECT query return the results
        # possible vulnerability here
        # any way to parametrize the query?
        if query.strip().lower().startswith("select"):
            results: List[Tuple[Any, ...]] = cursor.fetchall()
            return results
        conn.commit()
        return None
    finally:
        cursor.close()
        conn.close()
