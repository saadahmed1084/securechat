"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def encrypt_aes128_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: Data to encrypt
        key: 16-byte AES-128 key
        
    Returns:
        Encrypted ciphertext
        
    Raises:
        ValueError: If key length is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Add PKCS#7 padding
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes block size
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext


def decrypt_aes128_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-128 in ECB mode with PKCS#7 unpadding.
    
    Args:
        ciphertext: Encrypted data
        key: 16-byte AES-128 key
        
    Returns:
        Decrypted plaintext
        
    Raises:
        ValueError: If key length is not 16 bytes or decryption fails
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()  # 128 bits = 16 bytes block size
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()
    
    return plaintext
