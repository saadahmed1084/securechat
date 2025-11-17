"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
import hashlib
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

from app.common.utils import b64d, b64e


def load_private_key(key_path: Path) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from PEM file.
    
    Args:
        key_path: Path to private key file
        
    Returns:
        RSA private key object
    """
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Key is not an RSA private key")
        return private_key


def sign_hash(hash_value: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign a hash value using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        hash_value: SHA-256 hash value (32 bytes)
        private_key: RSA private key
        
    Returns:
        Signature bytes
    """
    if len(hash_value) != 32:
        raise ValueError("Hash must be 32 bytes (SHA-256)")
    
    signature = private_key.sign(
        hash_value,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Compute SHA-256 hash of data and sign it using RSA PKCS#1 v1.5.
    
    Args:
        data: Data to sign
        private_key: RSA private key
        
    Returns:
        Signature bytes
    """
    hash_value = hashlib.sha256(data).digest()
    return sign_hash(hash_value, private_key)


def verify_signature(
    signature: bytes,
    data: bytes,
    public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verify RSA signature using PKCS#1 v1.5 with SHA-256.
    
    Args:
        signature: Signature bytes
        data: Original data that was signed
        public_key: RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        hash_value = hashlib.sha256(data).digest()
        public_key.verify(
            signature,
            hash_value,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def verify_signature_from_certificate(
    signature: bytes,
    data: bytes,
    certificate: x509.Certificate
) -> bool:
    """
    Verify RSA signature using public key from certificate.
    
    Note: This assumes the signature is over SHA256(data), not over data directly.
    If you have a pre-computed hash, use verify_hash_from_certificate instead.
    
    Args:
        signature: Signature bytes
        data: Original data that was signed (signature is over SHA256(data))
        certificate: X.509 certificate containing the public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    return verify_signature(signature, data, public_key)


def verify_hash_from_certificate(
    signature: bytes,
    hash_value: bytes,
    certificate: x509.Certificate
) -> bool:
    """
    Verify RSA signature over a pre-computed hash value.
    
    Args:
        signature: Signature bytes
        hash_value: SHA-256 hash value (32 bytes) that was signed
        certificate: X.509 certificate containing the public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    
    try:
        public_key.verify(
            signature,
            hash_value,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def sign_hash_b64(hash_value: bytes, private_key: rsa.RSAPrivateKey) -> str:
    """
    Sign a hash and return base64-encoded signature.
    
    Args:
        hash_value: SHA-256 hash value (32 bytes)
        private_key: RSA private key
        
    Returns:
        Base64-encoded signature string
    """
    signature = sign_hash(hash_value, private_key)
    return b64e(signature)


def verify_signature_b64(
    signature_b64: str,
    data: bytes,
    public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verify base64-encoded RSA signature.
    
    Args:
        signature_b64: Base64-encoded signature
        data: Original data that was signed
        public_key: RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        signature = b64d(signature_b64)
        return verify_signature(signature, data, public_key)
    except Exception:
        return False
