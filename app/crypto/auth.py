"""Authentication helpers for encrypted registration/login payloads."""
from __future__ import annotations

import json
from typing import Tuple

from app.common.utils import b64d, b64e
from app.crypto.aes import decrypt_aes128_ecb, encrypt_aes128_ecb
from app.storage import db


# ---------------------------------------------------------------------------
# Payload encryption helpers (client-side usage)
# ---------------------------------------------------------------------------

def encrypt_registration_payload(
    email: str,
    username: str,
    password: str,
    aes_key: bytes,
) -> str:
    """Encrypt registration data using the temporary AES-128 key."""
    payload = {
        "email": email,
        "username": username,
        "password": password,
    }
    plaintext = json.dumps(payload).encode("utf-8")
    ciphertext = encrypt_aes128_ecb(plaintext, aes_key)
    return b64e(ciphertext)


def encrypt_login_payload(
    username: str,
    password: str,
    aes_key: bytes,
) -> str:
    """Encrypt login data using the temporary AES-128 key."""
    payload = {
        "username": username,
        "password": password,
    }
    plaintext = json.dumps(payload).encode("utf-8")
    ciphertext = encrypt_aes128_ecb(plaintext, aes_key)
    return b64e(ciphertext)


# ---------------------------------------------------------------------------
# Payload decryption helpers (server-side usage)
# ---------------------------------------------------------------------------

def _decrypt_payload(encrypted_data: str, aes_key: bytes) -> dict:
    """Base helper to decrypt and deserialize JSON payloads."""
    ciphertext = b64d(encrypted_data)
    plaintext = decrypt_aes128_ecb(ciphertext, aes_key)
    data = json.loads(plaintext.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Decrypted payload must be a JSON object")
    return data


def decrypt_registration_payload(
    encrypted_data: str,
    aes_key: bytes,
) -> Tuple[str, str, str]:
    """Return (email, username, password) from encrypted registration payload."""
    data = _decrypt_payload(encrypted_data, aes_key)
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")
    if not all([email, username, password]):
        raise ValueError("Registration payload missing fields")
    return email, username, password


def decrypt_login_payload(
    encrypted_data: str,
    aes_key: bytes,
) -> Tuple[str, str]:
    """Return (username, password) from encrypted login payload."""
    data = _decrypt_payload(encrypted_data, aes_key)
    username = data.get("username")
    password = data.get("password")
    if not all([username, password]):
        raise ValueError("Login payload missing fields")
    return username, password


# ---------------------------------------------------------------------------
# Server-side orchestration helpers
# ---------------------------------------------------------------------------

def handle_secure_registration(
    encrypted_payload: str,
    aes_key: bytes,
) -> Tuple[bool, str]:
    """
    Decrypt registration payload, store user in DB.

    Returns:
        (success, message)
    """
    try:
        email, username, password = decrypt_registration_payload(
            encrypted_payload,
            aes_key,
        )
    except ValueError as exc:
        return False, f"Malformed registration payload: {exc}"

    try:
        created = db.register_user(email=email, username=username, password=password)
        if not created:
            return False, "Username already exists"
    except Exception as exc:  # pragma: no cover - db layer raises
        return False, f"Database error: {exc}"

    return True, "OK"


def handle_secure_login(
    encrypted_payload: str,
    aes_key: bytes,
) -> Tuple[bool, str]:
    """
    Decrypt login payload and verify credentials.

    Returns:
        (success, message)
    """
    try:
        username, password = decrypt_login_payload(
            encrypted_payload,
            aes_key,
        )
    except ValueError as exc:
        return False, f"Malformed login payload: {exc}"

    try:
        is_valid = db.verify_user(username=username, password=password)
    except Exception as exc:  # pragma: no cover
        return False, f"Database error: {exc}"

    if not is_valid:
        return False, "Invalid credentials"

    return True, "OK"

