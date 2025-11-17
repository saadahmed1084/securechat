"""Message encryption, signing, decryption, and verification."""
import hashlib
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509

from app.common.utils import b64d, b64e, now_ms
from app.crypto.aes import decrypt_aes128_ecb, encrypt_aes128_ecb
from app.crypto.sign import load_private_key, verify_hash_from_certificate


def encrypt_and_sign_message(
    plaintext: str,
    seqno: int,
    session_key: bytes,
    private_key_path: Path
) -> Tuple[int, str, str]:
    """
    Encrypt and sign a message for transmission.
    
    Process:
    1. Pad plaintext with PKCS#7
    2. Encrypt with AES-128 using session key
    3. Compute hash: h = SHA256(seqno || timestamp || ciphertext)
    4. Sign hash with RSA private key
    5. Return timestamp, base64 ciphertext, base64 signature
    
    Args:
        plaintext: Plaintext message to encrypt
        seqno: Sequence number
        session_key: AES-128 session key (16 bytes)
        private_key_path: Path to RSA private key file
        
    Returns:
        Tuple of (timestamp_ms, base64_ciphertext, base64_signature)
    """
    # Get current timestamp
    timestamp = now_ms()
    
    # Encrypt plaintext with AES-128 (includes PKCS#7 padding)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = encrypt_aes128_ecb(plaintext_bytes, session_key)
    ciphertext_b64 = b64e(ciphertext)
    
    # Compute hash: h = SHA256(seqno || timestamp || ciphertext)
    # Convert seqno and timestamp to bytes (big-endian)
    seqno_bytes = seqno.to_bytes(8, byteorder='big')
    ts_bytes = timestamp.to_bytes(8, byteorder='big')
    hash_input = seqno_bytes + ts_bytes + ciphertext
    hash_value = hashlib.sha256(hash_input).digest()
    
    # Sign hash with RSA private key
    private_key = load_private_key(private_key_path)
    from app.crypto.sign import sign_hash_b64
    signature_b64 = sign_hash_b64(hash_value, private_key)
    
    return timestamp, ciphertext_b64, signature_b64


def decrypt_and_verify_message(
    seqno: int,
    timestamp: int,
    ciphertext_b64: str,
    signature_b64: str,
    session_key: bytes,
    sender_certificate: x509.Certificate,
    expected_seqno: int
) -> Tuple[bool, Optional[str], str]:
    """
    Decrypt and verify a received message.
    
    Process:
    1. Check seqno is strictly increasing (replay protection)
    2. Recompute hash: h = SHA256(seqno || timestamp || ciphertext)
    3. Verify signature using sender's certificate
    4. Decrypt ciphertext with AES-128 and remove PKCS#7 padding
    
    Args:
        seqno: Sequence number from message
        timestamp: Timestamp from message
        ciphertext_b64: Base64-encoded ciphertext
        signature_b64: Base64-encoded signature
        session_key: AES-128 session key (16 bytes)
        sender_certificate: Sender's X.509 certificate
        expected_seqno: Expected next sequence number
        
    Returns:
        Tuple of (success, plaintext, error_message)
        - success: True if message is valid, False otherwise
        - plaintext: Decrypted message if successful, None otherwise
        - error_message: Error description if failed, empty string if successful
    """
    # Step 1: Check sequence number is strictly increasing
    if seqno <= expected_seqno:
        return False, None, f"REPLAY: Sequence number {seqno} is not strictly increasing (expected > {expected_seqno})"
    
    # Step 2: Decode ciphertext
    try:
        ciphertext = b64d(ciphertext_b64)
    except Exception as e:
        return False, None, f"Invalid ciphertext encoding: {e}"
    
    # Step 3: Recompute hash: h = SHA256(seqno || timestamp || ciphertext)
    seqno_bytes = seqno.to_bytes(8, byteorder='big')
    ts_bytes = timestamp.to_bytes(8, byteorder='big')
    hash_input = seqno_bytes + ts_bytes + ciphertext
    hash_value = hashlib.sha256(hash_input).digest()
    
    # Step 4: Verify signature
    try:
        signature = b64d(signature_b64)
    except Exception as e:
        return False, None, f"Invalid signature encoding: {e}"
    
    # Verify signature using sender's certificate
    # The signature is over the hash value, not the data
    if not verify_hash_from_certificate(signature, hash_value, sender_certificate):
        return False, None, "SIG_FAIL: Signature verification failed"
    
    # Step 5: Decrypt ciphertext
    try:
        plaintext_bytes = decrypt_aes128_ecb(ciphertext, session_key)
        plaintext = plaintext_bytes.decode('utf-8')
    except Exception as e:
        return False, None, f"Decryption failed: {e}"
    
    return True, plaintext, ""

