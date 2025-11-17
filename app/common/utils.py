"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""
import base64
import hashlib
import time


def now_ms() -> int:
    """
    Get current timestamp in milliseconds since epoch.
    
    Returns:
        Current timestamp in milliseconds
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Base64 encode bytes to string.
    
    Args:
        b: Bytes to encode
        
    Returns:
        Base64 encoded string
    """
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str) -> bytes:
    """
    Base64 decode string to bytes.
    
    Args:
        s: Base64 encoded string
        
    Returns:
        Decoded bytes
    """
    return base64.b64decode(s.encode('utf-8'))


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hexadecimal string.
    
    Args:
        data: Data to hash
        
    Returns:
        SHA-256 hash as hexadecimal string (64 characters)
    """
    return hashlib.sha256(data).hexdigest()
