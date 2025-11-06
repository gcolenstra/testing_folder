"""
Database Helper Functions
Legacy code with security issues
"""

import sqlite3
import os

DATABASE_PATH = "users.db"

def init_db():
    """Initialize database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_user_by_username(username):
    """Get user by username - SECURITY ISSUE: SQL Injection!"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    # This is vulnerable to SQL injection!
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

def authenticate_user(username, password):
    """Authenticate user - SECURITY ISSUE: Plain text password!"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return True
    else:
        return False

def create_user(username, email, password):
    """Create new user - stores password in plain text!"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    from datetime import datetime
    created = datetime.now().isoformat()
    
    sql = "INSERT INTO users (username, email, password, created_at) VALUES ('%s', '%s', '%s', '%s')" % (
        username, email, password, created
    )
    cursor.execute(sql)
    conn.commit()
    conn.close()
    return True

def get_all_users():
    """Get all users"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users")
    users = cursor.fetchall()
    conn.close()
    
    result = []
    for user in users:
        result.append({
            "id": user[0],
            "username": user[1],
            "email": user[2]
        })
    return result

def delete_user(user_id):
    """Delete user by ID"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s" % user_id)
    conn.commit()
    conn.close()

def search_users(search_term):
    """Search users - SECURITY ISSUE: SQL Injection!"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username LIKE '%" + search_term + "%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results