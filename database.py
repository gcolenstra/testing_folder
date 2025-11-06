"""
Database Helper Functions
Refactored for Python 3.9+ with security improvements
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
import hashlib
import secrets

DATABASE_PATH = "users.db"


@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    
    Ensures proper connection handling with automatic cleanup.
    
    Yields:
        sqlite3.Connection: Database connection object
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
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
        str: Hashed password with salt (hex format)
    """
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{pwd_hash}"


def verify_password(stored_password: str, provided_password: str) -> bool:
    """
    Verify a password against its stored hash.
    
    Args:
        stored_password: Stored password hash with salt
        provided_password: Plain text password to verify
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        salt, pwd_hash = stored_password.split(':')
        new_hash = hashlib.sha256((provided_password + salt).encode()).hexdigest()
        return new_hash == pwd_hash
    except (ValueError, AttributeError):
        return False


def init_db() -> None:
    """
    Initialize database with users table.
    
    Creates the users table if it doesn't exist with proper schema.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def get_user_by_username(username: str) -> Optional[Tuple[Any, ...]]:
    """
    Get user by username using parameterized query.
    
    Args:
        username: Username to search for
        
    Returns:
        Optional[Tuple]: User data tuple if found, None otherwise
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
        user = cursor.fetchone()
        
        if user and verify_password(user[0], password):
            return True
        return False


def create_user(username: str, email: str, password: str) -> bool:
    """
    Create new user with hashed password storage.
    
    Args:
        username: Unique username for the new user
        email: User's email address
        password: Plain text password (will be hashed before storage)
        
    Returns:
        bool: True if user created successfully
        
    Raises:
        sqlite3.IntegrityError: If username already exists
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        created = datetime.now().isoformat()
        hashed_pwd = hash_password(password)
        
        cursor.execute(
            "INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?)",
            (username, email, hashed_pwd, created)
        )
        conn.commit()
        return True


def get_all_users() -> List[Dict[str, Any]]:
    """
    Get all users (excluding sensitive password data).
    
    Returns:
        List[Dict[str, Any]]: List of user dictionaries with id, username, and email
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
        user_id: ID of the user to delete
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()


def search_users(search_term: str) -> List[Tuple[Any, ...]]:
    """
    Search users by username using parameterized query.
    
    Args:
        search_term: Term to search for in usernames
        
    Returns:
        List[Tuple]: List of matching user data tuples
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username LIKE ?", 
            (f"%{search_term}%",)
        )
        results = cursor.fetchall()
        return results