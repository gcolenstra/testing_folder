"""
Database Helper Functions
Refactored with security improvements and modern Python practices
"""

import sqlite3
import os
from pathlib import Path
from typing import Optional, Any
from datetime import datetime
from contextlib import contextmanager
import hashlib
import secrets

DATABASE_PATH = "users.db"


@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    
    Ensures connections are properly closed even if errors occur.
    
    Yields:
        sqlite3.Connection: Active database connection
    """
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        yield conn
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """
    Hash a password using SHA-256 with salt.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        str: Salted and hashed password in format "salt$hash"
    """
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${pwd_hash}"


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        hashed: Stored hash in format "salt$hash"
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        salt, stored_hash = hashed.split('$')
        pwd_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        return pwd_hash == stored_hash
    except (ValueError, AttributeError):
        return False


def init_db() -> None:
    """
    Initialize database with users table.
    
    Creates the users table if it doesn't exist. Password field is designed
    to store hashed passwords with salt.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def get_user_by_username(username: str) -> Optional[tuple]:
    """
    Get user by username using parameterized query.
    
    Args:
        username: Username to search for
        
    Returns:
        Optional[tuple]: User record tuple or None if not found
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
    return result


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate user with hashed password verification.
    
    Args:
        username: Username to authenticate
        password: Plain text password to verify
        
    Returns:
        bool: True if authentication successful, False otherwise
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()
    
    if result:
        stored_hash = result[0]
        return verify_password(password, stored_hash)
    return False


def create_user(username: str, email: str, password: str) -> bool:
    """
    Create new user with hashed password.
    
    Args:
        username: Username for new user
        email: Email address for new user
        password: Plain text password (will be hashed)
        
    Returns:
        bool: True if user created successfully
        
    Raises:
        sqlite3.IntegrityError: If username already exists
    """
    hashed_password = hash_password(password)
    created = datetime.now().isoformat()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, created)
        )
        conn.commit()
    return True


def get_all_users() -> list[dict[str, Any]]:
    """
    Get all users without sensitive information.
    
    Returns:
        list[dict[str, Any]]: List of user dictionaries with id, username, email
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users")
        users = cursor.fetchall()
    
    return [
        {
            "id": user[0],
            "username": user[1],
            "email": user[2]
        }
        for user in users
    ]


def delete_user(user_id: int) -> None:
    """
    Delete user by ID using parameterized query.
    
    Args:
        user_id: ID of user to delete
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()


def search_users(search_term: str) -> list[tuple]:
    """
    Search users by username using parameterized query.
    
    Args:
        search_term: Term to search for in usernames
        
    Returns:
        list[tuple]: List of matching user records
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username LIKE ?",
            (f"%{search_term}%",)
        )
        results = cursor.fetchall()
    return results