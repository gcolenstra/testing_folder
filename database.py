"""
Database Helper Functions
Modernized for Python 3.9+ with security improvements
"""

import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
import hashlib
import secrets

DATABASE_PATH = "users.db"


@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    
    Ensures proper connection handling and automatic cleanup.
    
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
        str: Salted and hashed password
        
    Note:
        In production, use bcrypt or argon2 instead of SHA-256
    """
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${hashed}"


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        hashed_password: Stored salted hash to check against
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        salt, stored_hash = hashed_password.split('$')
        computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return computed_hash == stored_hash
    except (ValueError, AttributeError):
        return False


def init_db() -> None:
    """
    Initialize database schema.
    
    Creates the users table if it doesn't exist with proper schema.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def get_user_by_username(username: str) -> Optional[Tuple]:
    """
    Get user by username using parameterized query.
    
    Args:
        username: Username to search for
        
    Returns:
        Optional[Tuple]: User data tuple if found, None otherwise
        
    Security:
        Uses parameterized queries to prevent SQL injection
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
        
    Security:
        - Uses parameterized queries to prevent SQL injection
        - Verifies against hashed passwords instead of plain text
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if user and verify_password(password, user[0]):
            return True
        return False


def create_user(username: str, email: str, password: str) -> bool:
    """
    Create new user with hashed password.
    
    Args:
        username: Desired username
        email: User email address
        password: Plain text password (will be hashed)
        
    Returns:
        bool: True if user created successfully
        
    Security:
        - Uses parameterized queries to prevent SQL injection
        - Stores hashed passwords instead of plain text
        
    Raises:
        sqlite3.IntegrityError: If username or email already exists
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        created = datetime.now().isoformat()
        hashed_pw = hash_password(password)
        
        cursor.execute(
            "INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?)",
            (username, email, hashed_pw, created)
        )
        conn.commit()
        return True


def get_all_users() -> List[Dict[str, Any]]:
    """
    Get all users (excluding passwords).
    
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
        user_id: ID of user to delete
        
    Security:
        Uses parameterized queries to prevent SQL injection
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()


def search_users(search_term: str) -> List[Tuple]:
    """
    Search users by username using parameterized query.
    
    Args:
        search_term: Search term to match against usernames
        
    Returns:
        List[Tuple]: List of matching user records
        
    Security:
        Uses parameterized queries to prevent SQL injection
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username LIKE ?",
            (f"%{search_term}%",)
        )
        results = cursor.fetchall()
        return results