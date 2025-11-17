"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from typing import Optional
from pydantic import BaseModel, Field


class Hello(BaseModel):
    """Client hello message - initiates connection."""
    type: str = Field(default="hello", description="Message type")
    cert: str = Field(description="Client certificate (base64 encoded PEM)")


class ServerHello(BaseModel):
    """Server hello response - includes server certificate."""
    type: str = Field(default="server_hello", description="Message type")
    cert: str = Field(description="Server certificate (base64 encoded PEM)")


class DHClient(BaseModel):
    """Client DH public key message."""
    type: str = Field(default="dh_client", description="Message type")
    dh_pubkey: str = Field(description="Client DH public key (base64 encoded PEM)")


class DHServer(BaseModel):
    """Server DH public key message."""
    type: str = Field(default="dh_server", description="Message type")
    dh_pubkey: str = Field(description="Server DH public key (base64 encoded PEM)")


class Register(BaseModel):
    """Registration request with encrypted credentials."""
    type: str = Field(default="register", description="Message type")
    encrypted_data: str = Field(description="Encrypted registration data (base64 encoded)")
    # Encrypted data contains: email, username, password (JSON format)


class RegisterResponse(BaseModel):
    """Registration response."""
    type: str = Field(default="register_response", description="Message type")
    status: str = Field(description="Status: 'OK' or error message")


class Login(BaseModel):
    """Login request with encrypted credentials."""
    type: str = Field(default="login", description="Message type")
    encrypted_data: str = Field(description="Encrypted login data (base64 encoded)")
    # Encrypted data contains: username, password (JSON format)


class LoginResponse(BaseModel):
    """Login response."""
    type: str = Field(default="login_response", description="Message type")
    status: str = Field(description="Status: 'OK' or error message")


class SessionKeyEstablished(BaseModel):
    """Confirmation that session key has been established."""
    type: str = Field(default="session_key_established", description="Message type")
    status: str = Field(default="OK", description="Status: 'OK' or error message")


class Message(BaseModel):
    """Chat message with encryption and signature."""
    type: str = Field(default="msg", description="Message type")
    seqno: int = Field(description="Sequence number")
    ts: int = Field(description="Unix timestamp in milliseconds")
    ct: str = Field(description="Encrypted ciphertext (base64 encoded)")
    sig: str = Field(description="RSA signature of SHA256(seqno||ts||ct) (base64 encoded)")


class Receipt(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = Field(default="receipt", description="Message type")
    session_id: str = Field(description="Session identifier")
    transcript_hash: str = Field(description="SHA256 hash of transcript")
    signature: str = Field(description="Receipt signature (base64 encoded)")


class ErrorResponse(BaseModel):
    """Error response."""
    type: str = Field(default="error", description="Message type")
    error: str = Field(description="Error code: BAD_CERT, SIG_FAIL, REPLAY, etc.")
