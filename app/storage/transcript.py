"""Append-only transcript + TranscriptHash helpers."""
import hashlib
from pathlib import Path
from typing import Optional

from cryptography import x509

from app.common.utils import sha256_hex


def get_certificate_fingerprint(certificate: x509.Certificate) -> str:
    """
    Compute SHA-256 fingerprint of a certificate.
    
    Args:
        certificate: X.509 certificate
        
    Returns:
        Hexadecimal string of SHA-256 hash (64 characters)
    """
    cert_bytes = certificate.public_bytes(x509.Encoding.PEM)
    return sha256_hex(cert_bytes)


def append_to_transcript(
    transcript_path: Path,
    seqno: int,
    timestamp: int,
    ciphertext_b64: str,
    signature_b64: str,
    peer_cert_fingerprint: str
) -> None:
    """
    Append a message entry to the append-only transcript file.
    
    Format: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
    
    Args:
        transcript_path: Path to transcript file
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext_b64: Base64-encoded ciphertext
        signature_b64: Base64-encoded signature
        peer_cert_fingerprint: SHA-256 fingerprint of peer's certificate (hex)
    """
    # Create transcripts directory if it doesn't exist
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Format: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
    line = f"{seqno}|{timestamp}|{ciphertext_b64}|{signature_b64}|{peer_cert_fingerprint}\n"
    
    # Append to file (append-only)
    with open(transcript_path, "a", encoding="utf-8") as f:
        f.write(line)


def compute_transcript_hash(transcript_path: Path) -> Optional[str]:
    """
    Compute SHA-256 hash of the entire transcript file.
    
    TranscriptHash = SHA256(concatenation of all log lines)
    
    Args:
        transcript_path: Path to transcript file
        
    Returns:
        Hexadecimal string of SHA-256 hash (64 characters), or None if file doesn't exist
    """
    if not transcript_path.exists():
        return None
    
    # Read entire file
    with open(transcript_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Compute SHA-256 hash of the entire content
    hash_bytes = hashlib.sha256(content.encode("utf-8")).digest()
    return hash_bytes.hex()


def get_transcript_range(transcript_path: Path) -> tuple[Optional[int], Optional[int]]:
    """
    Get the first and last sequence numbers from transcript.
    
    Args:
        transcript_path: Path to transcript file
        
    Returns:
        Tuple of (first_seq, last_seq), or (None, None) if file doesn't exist or is empty
    """
    if not transcript_path.exists():
        return None, None
    
    first_seq = None
    last_seq = None
    
    with open(transcript_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Parse: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
            parts = line.split("|")
            if len(parts) >= 1:
                try:
                    seqno = int(parts[0])
                    if first_seq is None:
                        first_seq = seqno
                    last_seq = seqno
                except ValueError:
                    continue
    
    return first_seq, last_seq


def verify_transcript_integrity(transcript_path: Path, expected_hash: str) -> bool:
    """
    Verify that transcript file matches the expected hash.
    
    Args:
        transcript_path: Path to transcript file
        expected_hash: Expected SHA-256 hash (hex)
        
    Returns:
        True if transcript hash matches expected hash, False otherwise
    """
    actual_hash = compute_transcript_hash(transcript_path)
    if actual_hash is None:
        return False
    
    return actual_hash.lower() == expected_hash.lower()
