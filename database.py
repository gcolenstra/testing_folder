"""
Database Helper Functions
Secure and modernized database operations with proper error handling
"""

import sqlite3
import hashlib
import secrets
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from contextlib import contextmanager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_PATH = "users.db"


@contextmanager
def get_db_connection():
    """
    Context manager for database connections with proper error handling.
    
    Yields:
        sqlite3.Connection: Database connection object
        
    Raises:
        sqlite3.Error: If database connection fails
    """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        yield conn
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()


def hash_password(password: str) -> Tuple[str, str]:
    """
    Hash a password with a random salt using SHA-256.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Tuple containing (hashed_password, salt)
    """
    salt = secrets.token_hex(32)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return password_hash, salt


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """
    Verify a password against its hash and salt.
    
    Args:
        password: Plain text password to verify
        hashed_password: Stored password hash
        salt: Salt used for hashing
        
    Returns:
        True if password matches, False otherwise
    """
    return hashlib.sha256((password + salt).encode()).hexdigest() == hashed_password


def init_db() -> None:
    """
    Initialize the database and create the users table if it doesn't exist.
    
    Raises:
        sqlite3.Error: If database initialization fails
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()
            logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """
    Get user by username using parameterized query to prevent SQL injection.
    
    Args:
        username: Username to search for
        
    Returns:
        Dictionary containing user data if found, None otherwise
        
    Raises:
        sqlite3.Error: If database query fails
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            
            if result:
                return {
                    "id": result["id"],
                    "username": result["username"],
                    "email": result["email"],
                    "password_hash": result["password_hash"],
                    "salt": result["salt"],
                    "created_at": result["created_at"]
                }
            return None
    except sqlite3.Error as e:
        logger.error(f"Failed to get user by username: {e}")
        raise


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate user with secure password verification.
    
    Args:
        username: Username to authenticate
        password: Plain text password
        
    Returns:
        True if authentication successful, False otherwise
        
    Raises:
        sqlite3.Error: If database query fails
    """
    try:
        user = get_user_by_username(username)
        if user:
            return verify_password(password, user["password_hash"], user["salt"])
        return False
    except sqlite3.Error as e:
        logger.error(f"Failed to authenticate user: {e}")
        raise


def create_user(username: str, email: str, password: str) -> bool:
    """
    Create new user with secure password hashing.
    
    Args:
        username: Unique username
        email: User's email address
        password: Plain text password (will be hashed)
        
    Returns:
        True if user created successfully
        
    Raises:
        sqlite3.Error: If user creation fails
        ValueError: If username or email already exists
    """
    try:
        password_hash, salt = hash_password(password)
        created_at = datetime.now().isoformat()
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, email, password_hash, salt, created_at)
            )
            conn.commit()
            logger.info(f"User '{username}' created successfully")
            return True
            
    except sqlite3.IntegrityError as e:
        if "username" in str(e).lower():
            raise ValueError(f"Username '{username}' already exists")
        elif "email" in str(e).lower():
            raise ValueError(f"Email '{email}' already exists")
        else:
            raise ValueError("User creation failed due to constraint violation")
    except sqlite3.Error as e:
        logger.error(f"Failed to create user: {e}")
        raise


def get_all_users() -> List[Dict[str, Any]]:
    """
    Get all users (excluding sensitive password information).
    
    Returns:
        List of dictionaries containing user data
        
    Raises:
        sqlite3.Error: If database query fails
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, created_at FROM users")
            users = cursor.fetchall()
            
            return [
                {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "created_at": user["created_at"]
                }
                for user in users
            ]
    except sqlite3.Error as e:
        logger.error(f"Failed to get all users: {e}")
        raise


def delete_user(user_id: int) -> bool:
    """
    Delete user by ID using parameterized query.
    
    Args:
        user_id: ID of user to delete
        
    Returns:
        True if user was deleted, False if user not found
        
    Raises:
        sqlite3.Error: If database operation fails
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"User with ID {user_id} deleted successfully")
                return True
            else:
                logger.warning(f"No user found with ID {user_id}")
                return False
                
    except sqlite3.Error as e:
        logger.error(f"Failed to delete user: {e}")
        raise


def search_users(search_term: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Search users by username using secure parameterized query.
    
    Args:
        search_term: Term to search for in usernames
        limit: Maximum number of results to return (default: 100)
        
    Returns:
        List of dictionaries containing matching user data
        
    Raises:
        sqlite3.Error: If database query fails
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            search_pattern = f"%{search_term}%"
            cursor.execute(
                "SELECT id, username, email, created_at FROM users WHERE username LIKE ? LIMIT ?",
                (search_pattern, limit)
            )
            results = cursor.fetchall()
            
            return [
                {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "created_at": user["created_at"]
                }
                for user in results
            ]
    except sqlite3.Error as e:
        logger.error(f"Failed to search users: {e}")
        raise


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Get user by ID (excluding sensitive password information).
    
    Args:
        user_id: ID of user to retrieve
        
    Returns:
        Dictionary containing user data if found, None otherwise
        
    Raises:
        sqlite3.Error: If database query fails
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, created_at FROM users WHERE id = ?",
                (user_id,)
            )
            result = cursor.fetchone()
            
            if result:
                return {
                    "id": result["id"],
                    "username": result["username"],
                    "email": result["email"],
                    "created_at": result["created_at"]
                }
            return None
    except sqlite3.Error as e:
        logger.error(f"Failed to get user by ID: {e}")
        raise


def update_user_email(user_id: int, new_email: str) -> bool:
    """
    Update user's email address.
    
    Args:
        user_id: ID of user to update
        new_email: New email address
        
    Returns:
        True if update successful, False if user not found
        
    Raises:
        sqlite3.Error: If database operation fails
        ValueError: If email already exists
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET email = ? WHERE id = ?",
                (new_email, user_id)
            )
            conn.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"Email updated for user ID {user_id}")
                return True
            else:
                logger.warning(f"No user found with ID {user_id}")
                return False
                
    except sqlite3.IntegrityError:
        raise ValueError(f"Email '{new_email}' already exists")
    except sqlite3.Error as e:
        logger.error(f"Failed to update user email: {e}")
        raise