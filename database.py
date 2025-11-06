"""
Database Helper Functions
Refactored for Python 3.9+ with security improvements
"""

import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List, Dict, Any
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


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """
    Hash a password using PBKDF2 with SHA-256.
    
    Args:
        password: Plain text password to hash
        salt: Optional salt bytes, generated if not provided
        
    Returns:
        tuple: (hashed_password_hex, salt_hex)
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return pwd_hash.hex(), salt.hex()


def init_db() -> None:
    """
    Initialize database with users table.
    
    Creates the users table if it doesn't exist. Updated to include
    salt field for password hashing.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    """
    Get user by username using parameterized query.
    
    Args:
        username: Username to search for
        
    Returns:
        User row if found, None otherwise
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
            "SELECT password, salt FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            return False
        
        stored_hash = user['password']
        salt = bytes.fromhex(user['salt'])
        
        # Hash the provided password with stored salt
        computed_hash, _ = hash_password(password, salt)
        
        return computed_hash == stored_hash


def create_user(username: str, email: str, password: str) -> bool:
    """
    Create new user with hashed password.
    
    Args:
        username: Unique username
        email: User email address
        password: Plain text password (will be hashed)
        
    Returns:
        bool: True if user created successfully
        
    Raises:
        sqlite3.IntegrityError: If username already exists
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        created = datetime.now().isoformat()
        
        # Hash password with generated salt
        pwd_hash, salt = hash_password(password)
        
        cursor.execute(
            "INSERT INTO users (username, email, password, salt, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, email, pwd_hash, salt, created)
        )
        conn.commit()
        return True


def get_all_users() -> List[Dict[str, Any]]:
    """
    Get all users without sensitive information.
    
    Returns:
        List of user dictionaries containing id, username, and email
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users")
        users = cursor.fetchall()
        
        return [
            {
                "id": user['id'],
                "username": user['username'],
                "email": user['email']
            }
            for user in users
        ]


def delete_user(user_id: int) -> None:
    """
    Delete user by ID using parameterized query.
    
    Args:
        user_id: User ID to delete
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()


def search_users(search_term: str) -> List[sqlite3.Row]:
    """
    Search users by username using parameterized query.
    
    Args:
        search_term: Term to search for in usernames
        
    Returns:
        List of matching user rows
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username LIKE ?",
            (f"%{search_term}%",)
        )
        results = cursor.fetchall()
        return results