"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


# Standard DH parameters (2048-bit MODP group)
# Generate once and reuse for all keypairs to ensure compatibility
# Both parties must use the same parameters
_backend = default_backend()
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048, backend=_backend)


def generate_dh_keypair() -> Tuple[dh.DHPrivateKey, dh.DHPublicKey]:
    """
    Generate a Diffie-Hellman keypair.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def compute_shared_secret(private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey) -> bytes:
    """
    Compute the shared secret from our private key and peer's public key.
    
    Args:
        private_key: Our DH private key
        peer_public_key: Peer's DH public key
        
    Returns:
        Shared secret as bytes
    """
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive AES-128 key from shared secret using: K = Trunc_16(SHA256(big-endian(K_s)))
    
    The shared secret K_s is converted to a temporary AES-128 key K using:
    K = Trunc_16(SHA256(big-endian(K_s))
    
    Args:
        shared_secret: The shared secret K_s from DH exchange (bytes)
        
    Returns:
        16-byte AES-128 key
    """
    # K_s is already in big-endian format (bytes are naturally big-endian)
    # Compute SHA256(K_s)
    hash_value = hashlib.sha256(shared_secret).digest()
    
    # Truncate to 16 bytes (128 bits) for AES-128
    aes_key = hash_value[:16]
    
    return aes_key


def serialize_public_key(public_key: dh.DHPublicKey) -> bytes:
    """
    Serialize DH public key to bytes for transmission.
    
    Args:
        public_key: DH public key to serialize
        
    Returns:
        Serialized public key as bytes
    """
    return public_key.public_bytes(
        encoding=dh.Encoding.PEM,
        format=dh.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(public_key_data: bytes) -> dh.DHPublicKey:
    """
    Deserialize DH public key from bytes.
    
    The public key must have been generated with the same DH parameters.
    
    Args:
        public_key_data: Serialized public key bytes (PEM format)
        
    Returns:
        DH public key object
    """
    # Load the public key - it should use the same parameters
    # The parameters are embedded in the PEM format
    return dh.load_pem_public_key(public_key_data, backend=_backend)
