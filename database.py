"""
Database Helper Functions
Refactored code with security improvements
"""

import sqlite3
import os
import bcrypt
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

DATABASE_PATH = os.getenv("DATABASE_PATH", "users.db")

@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
    try:
        yield conn
    finally:
        conn.close()

def init_db() -> None:
    """Initialize database with users table."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()

def hash_password(password: str) -> str:
    """Hash a password using bcrypt.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Hashed password string
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        password_hash: Stored password hash
        
    Returns:
        True if password matches, False otherwise
    """
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get user by username using parameterized query.
    
    Args:
        username: Username to search for
        
    Returns:
        User dictionary if found, None otherwise
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            return dict(result)
    return None

def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user with secure password verification.
    
    Args:
        username: Username to authenticate
        password: Plain text password
        
    Returns:
        True if authentication successful, False otherwise
    """
    user = get_user_by_username(username)
    if user and verify_password(password, user['password_hash']):
        return True
    return False

def create_user(username: str, email: str, password: str) -> bool:
    """Create new user with hashed password.
    
    Args:
        username: Unique username
        email: User email address
        password: Plain text password (will be hashed)
        
    Returns:
        True if user created successfully
        
    Raises:
        sqlite3.IntegrityError: If username or email already exists
    """
    password_hash = hash_password(password)
    created = datetime.now().isoformat()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, created)
        )
        conn.commit()
    return True

def get_all_users() -> List[Dict[str, Any]]:
    """Get all users (excluding password hashes).
    
    Returns:
        List of user dictionaries with id, username, email, and created_at
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, created_at FROM users")
        users = cursor.fetchall()
    
    return [dict(user) for user in users]

def delete_user(user_id: int) -> bool:
    """Delete user by ID using parameterized query.
    
    Args:
        user_id: ID of user to delete
        
    Returns:
        True if user was deleted, False if user not found
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount > 0

def search_users(search_term: str) -> List[Dict[str, Any]]:
    """Search users by username using parameterized query.
    
    Args:
        search_term: Term to search for in usernames
        
    Returns:
        List of matching user dictionaries (excluding password hashes)
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, created_at FROM users WHERE username LIKE ?",
            (f"%{search_term}%",)
        )
        results = cursor.fetchall()
    
    return [dict(user) for user in results]