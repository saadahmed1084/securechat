"""Session receipt generation and verification for non-repudiation."""
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509

from app.common.protocol import Receipt
from app.common.utils import b64e
from app.crypto.sign import load_private_key, sign_hash_b64, verify_hash_from_certificate
from app.storage import transcript


def generate_session_receipt(
    transcript_path: Path,
    peer: str,
    private_key_path: Path
) -> Optional[Receipt]:
    """
    Generate a signed session receipt from transcript.
    
    Process:
    1. Compute transcript hash: SHA256(concatenation of all log lines)
    2. Get first and last sequence numbers
    3. Sign transcript hash with RSA private key
    4. Create Receipt object
    
    Args:
        transcript_path: Path to transcript file
        peer: Peer identifier ("client" or "server")
        private_key_path: Path to RSA private key for signing
        
    Returns:
        Receipt object if successful, None otherwise
    """
    # Compute transcript hash
    transcript_hash = transcript.compute_transcript_hash(transcript_path)
    if transcript_hash is None:
        return None
    
    # Get sequence number range
    first_seq, last_seq = transcript.get_transcript_range(transcript_path)
    if first_seq is None or last_seq is None:
        return None
    
    # Sign transcript hash
    try:
        private_key = load_private_key(private_key_path)
        import hashlib
        hash_bytes = bytes.fromhex(transcript_hash)
        signature_b64 = sign_hash_b64(hash_bytes, private_key)
    except Exception as e:
        return None
    
    # Create receipt
    receipt = Receipt(
        peer=peer,
        first_seq=first_seq,
        last_seq=last_seq,
        transcript_sha256=transcript_hash,
        sig=signature_b64
    )
    
    return receipt


def verify_session_receipt(
    receipt: Receipt,
    transcript_path: Path,
    signer_certificate: x509.Certificate
) -> Tuple[bool, str]:
    """
    Verify a session receipt.
    
    Process:
    1. Verify transcript hash matches computed hash
    2. Verify signature using signer's certificate
    3. Check sequence number range matches transcript
    
    Args:
        receipt: Receipt to verify
        transcript_path: Path to transcript file
        signer_certificate: Certificate of the signer
        
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if receipt is valid, False otherwise
        - error_message: Empty string if valid, error description otherwise
    """
    # Step 1: Compute transcript hash and compare
    computed_hash = transcript.compute_transcript_hash(transcript_path)
    if computed_hash is None:
        return False, "Transcript file not found or empty"
    
    if computed_hash.lower() != receipt.transcript_sha256.lower():
        return False, f"Transcript hash mismatch: expected {computed_hash}, got {receipt.transcript_sha256}"
    
    # Step 2: Verify signature
    try:
        import hashlib
        from app.common.utils import b64d
        hash_bytes = bytes.fromhex(receipt.transcript_sha256)
        signature = b64d(receipt.sig)
        
        if not verify_hash_from_certificate(signature, hash_bytes, signer_certificate):
            return False, "Signature verification failed"
    except Exception as e:
        return False, f"Signature verification error: {e}"
    
    # Step 3: Verify sequence number range
    first_seq, last_seq = transcript.get_transcript_range(transcript_path)
    if first_seq is None or last_seq is None:
        return False, "Could not determine sequence number range from transcript"
    
    if first_seq != receipt.first_seq:
        return False, f"First sequence number mismatch: expected {first_seq}, got {receipt.first_seq}"
    
    if last_seq != receipt.last_seq:
        return False, f"Last sequence number mismatch: expected {last_seq}, got {receipt.last_seq}"
    
    return True, ""


def save_receipt(receipt: Receipt, output_path: Path) -> None:
    """
    Save receipt to file as JSON.
    
    Args:
        receipt: Receipt to save
        output_path: Path to output file
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(receipt.model_dump_json(indent=2))


def load_receipt(receipt_path: Path) -> Optional[Receipt]:
    """
    Load receipt from JSON file.
    
    Args:
        receipt_path: Path to receipt file
        
    Returns:
        Receipt object if successful, None otherwise
    """
    if not receipt_path.exists():
        return None
    
    try:
        with open(receipt_path, "r", encoding="utf-8") as f:
            return Receipt.model_validate_json(f.read())
    except Exception as e:
        return None


def verify_receipt_offline(
    receipt_path: Path,
    transcript_path: Path,
    signer_cert_path: Path
) -> Tuple[bool, str]:
    """
    Offline verification of a session receipt.
    
    This function can be used to verify receipts after the session has ended,
    providing non-repudiation evidence.
    
    Process:
    1. Load receipt from file
    2. Load signer's certificate
    3. Verify receipt against transcript
    
    Args:
        receipt_path: Path to receipt JSON file
        transcript_path: Path to transcript file
        signer_cert_path: Path to signer's certificate file
        
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if receipt is valid, False otherwise
        - error_message: Empty string if valid, error description otherwise
    """
    # Load receipt
    receipt_obj = load_receipt(receipt_path)
    if receipt_obj is None:
        return False, "Could not load receipt from file"
    
    # Load signer's certificate
    try:
        from cryptography import x509
        with open(signer_cert_path, "rb") as f:
            signer_cert = x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        return False, f"Could not load signer certificate: {e}"
    
    # Verify receipt
    is_valid, error_msg = verify_session_receipt(
        receipt=receipt_obj,
        transcript_path=transcript_path,
        signer_certificate=signer_cert
    )
    
    return is_valid, error_msg
