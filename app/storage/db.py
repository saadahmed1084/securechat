"""MySQL users table + salted hashing (no chat storage)."""
import argparse
import hashlib
import os
from pathlib import Path
from typing import Optional, Tuple

import pymysql
from dotenv import load_dotenv


# Load environment variables
env_path = Path(__file__).parent.parent.parent / '.env'
if env_path.exists():
    load_dotenv(env_path)


def get_db_connection():
    """
    Get MySQL database connection.
    
    Returns:
        Database connection object
    """
    return pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'scuser'),
        password=os.getenv('DB_PASSWORD', 'scpass'),
        database=os.getenv('DB_NAME', 'securechat'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


def init_database():
    """
    Initialize the database schema.
    Creates the users table if it doesn't exist.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    PRIMARY KEY (username),
                    INDEX idx_email (email)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
        conn.commit()
        print("✓ Database initialized successfully")
    except Exception as e:
        print(f"✗ Error initializing database: {e}")
        raise
    finally:
        conn.close()


def generate_salt() -> bytes:
    """
    Generate a random 16-byte salt.
    
    Returns:
        16-byte random salt
    """
    return os.urandom(16)


def compute_password_hash(password: str, salt: bytes) -> str:
    """
    Compute salted password hash: pwd_hash = hex(SHA256(salt || password))
    
    Args:
        password: Plaintext password
        salt: 16-byte salt
        
    Returns:
        Hexadecimal string of SHA256 hash (64 characters)
    """
    # Concatenate salt and password
    salted_password = salt + password.encode('utf-8')
    
    # Compute SHA256 hash
    hash_bytes = hashlib.sha256(salted_password).digest()
    
    # Return as hexadecimal string
    return hash_bytes.hex()


def register_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user with salted password hash.
    
    Args:
        email: User's email address
        username: Unique username
        password: Plaintext password
        
    Returns:
        True if registration successful, False if username already exists
    """
    conn = get_db_connection()
    try:
        # Generate salt
        salt = generate_salt()
        
        # Compute password hash
        pwd_hash = compute_password_hash(password, salt)
        
        with conn.cursor() as cursor:
            # Insert user
            cursor.execute("""
                INSERT INTO users (email, username, salt, pwd_hash)
                VALUES (%s, %s, %s, %s)
            """, (email, username, salt, pwd_hash))
        conn.commit()
        return True
    except pymysql.err.IntegrityError:
        # Username already exists
        return False
    except Exception as e:
        print(f"Error registering user: {e}")
        raise
    finally:
        conn.close()


def verify_user(username: str, password: str) -> Optional[Tuple[str, bytes, str]]:
    """
    Verify user credentials by recomputing salted hash.
    
    Args:
        username: Username to verify
        password: Plaintext password to verify
        
    Returns:
        Tuple of (email, salt, pwd_hash) if credentials are valid, None otherwise
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Get user record
            cursor.execute("""
                SELECT email, salt, pwd_hash
                FROM users
                WHERE username = %s
            """, (username,))
            result = cursor.fetchone()
            
            if not result:
                return None
            
            # Get stored salt and hash
            stored_salt = result['salt']
            stored_pwd_hash = result['pwd_hash']
            
            # Recompute hash with provided password
            computed_hash = compute_password_hash(password, stored_salt)
            
            # Verify hash matches
            if computed_hash == stored_pwd_hash:
                return (result['email'], stored_salt, stored_pwd_hash)
            else:
                return None
    except Exception as e:
        print(f"Error verifying user: {e}")
        raise
    finally:
        conn.close()


def get_user_salt(username: str) -> Optional[bytes]:
    """
    Get the salt for a user (for testing/debugging purposes).
    
    Args:
        username: Username
        
    Returns:
        Salt bytes if user exists, None otherwise
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT salt
                FROM users
                WHERE username = %s
            """, (username,))
            result = cursor.fetchone()
            if result:
                return result['salt']
            return None
    except Exception as e:
        print(f"Error getting user salt: {e}")
        raise
    finally:
        conn.close()


def user_exists(username: str) -> bool:
    """
    Check if a user exists.
    
    Args:
        username: Username to check
        
    Returns:
        True if user exists, False otherwise
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT 1
                FROM users
                WHERE username = %s
            """, (username,))
            return cursor.fetchone() is not None
    except Exception as e:
        print(f"Error checking user existence: {e}")
        raise
    finally:
        conn.close()


def main():
    """CLI entry point for database initialization."""
    parser = argparse.ArgumentParser(description="Database management")
    parser.add_argument('--init', action='store_true', help='Initialize database schema')
    args = parser.parse_args()
    
    if args.init:
        init_database()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
