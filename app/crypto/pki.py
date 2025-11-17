"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID, ExtensionOID, SignatureAlgorithmOID


class PKIError(Exception):
    """Base exception for PKI validation errors."""
    pass


class BadCertificateError(PKIError):
    """Raised when certificate validation fails."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"BAD_CERT: {reason}")


def load_ca_certificate(ca_cert_path: Path) -> x509.Certificate:
    """
    Load CA certificate from file.
    
    Args:
        ca_cert_path: Path to CA certificate file
        
    Returns:
        CA certificate object
        
    Raises:
        FileNotFoundError: If CA certificate file doesn't exist
        ValueError: If certificate cannot be loaded
    """
    if not ca_cert_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
    
    with open(ca_cert_path, "rb") as f:
        cert_data = f.read()
        try:
            return x509.load_pem_x509_certificate(cert_data)
        except ValueError:
            # Try DER format as fallback
            return x509.load_der_x509_certificate(cert_data)


def load_certificate(cert_data: bytes) -> x509.Certificate:
    """
    Load X.509 certificate from bytes (PEM or DER format).
    
    Args:
        cert_data: Certificate data in PEM or DER format
        
    Returns:
        Certificate object
        
    Raises:
        ValueError: If certificate cannot be loaded
    """
    try:
        return x509.load_pem_x509_certificate(cert_data)
    except ValueError:
        # Try DER format as fallback
        return x509.load_der_x509_certificate(cert_data)


def verify_certificate_signature(
    certificate: x509.Certificate,
    issuer_certificate: x509.Certificate
) -> bool:
    """
    Verify that a certificate is signed by the issuer certificate.
    
    Args:
        certificate: Certificate to verify
        issuer_certificate: Issuer's certificate (CA certificate)
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Get the issuer's public key
        issuer_public_key = issuer_certificate.public_key()
        
        # Determine the hash algorithm from the signature algorithm
        sig_alg = certificate.signature_algorithm_oid
        hash_alg = None
        
        # Map signature algorithm OIDs to hash algorithms
        if sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA256:
            hash_alg = hashes.SHA256()
        elif sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA384:
            hash_alg = hashes.SHA384()
        elif sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA512:
            hash_alg = hashes.SHA512()
        elif sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA1:
            hash_alg = hashes.SHA1()
        else:
            # Default to SHA256 if unknown
            hash_alg = hashes.SHA256()
        
        # Verify the signature using the issuer's public key
        # The signature is over the TBS (To Be Signed) certificate bytes
        
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_alg
        )
        
        return True
    except (InvalidSignature, AttributeError, ValueError, TypeError) as e:
        return False


def is_self_signed(certificate: x509.Certificate) -> bool:
    """
    Check if a certificate is self-signed (subject == issuer).
    
    Args:
        certificate: Certificate to check
        
    Returns:
        True if self-signed, False otherwise
    """
    return certificate.subject == certificate.issuer


def check_certificate_validity(certificate: x509.Certificate, current_time: Optional[datetime] = None) -> bool:
    """
    Check if certificate is within its validity period.
    
    Args:
        certificate: Certificate to check
        current_time: Current time (default: UTC now)
        
    Returns:
        True if certificate is valid, False if expired or not yet valid
    """
    if current_time is None:
        current_time = datetime.utcnow()
    
    return certificate.not_valid_before <= current_time <= certificate.not_valid_after


def get_certificate_cn(certificate: x509.Certificate) -> Optional[str]:
    """
    Extract Common Name (CN) from certificate subject.
    
    Args:
        certificate: Certificate to extract CN from
        
    Returns:
        Common Name string, or None if not found
    """
    try:
        cn_attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attributes:
            return cn_attributes[0].value
    except (AttributeError, IndexError):
        pass
    return None


def get_certificate_san_dns_names(certificate: x509.Certificate):
    """
    Extract DNS names from Subject Alternative Name (SAN) extension.
    
    Args:
        certificate: Certificate to extract SAN from
        
    Returns:
        List of DNS names from SAN extension
    """
    dns_names = []
    try:
        san_ext = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                dns_names.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return dns_names


def check_hostname_match(certificate: x509.Certificate, expected_hostname: str) -> bool:
    """
    Check if certificate's CN or SAN matches the expected hostname.
    
    Args:
        certificate: Certificate to check
        expected_hostname: Expected hostname/CN
        
    Returns:
        True if hostname matches, False otherwise
    """
    # Check CN
    cn = get_certificate_cn(certificate)
    if cn and cn.lower() == expected_hostname.lower():
        return True
    
    # Check SAN DNS names
    dns_names = get_certificate_san_dns_names(certificate)
    for dns_name in dns_names:
        if dns_name.lower() == expected_hostname.lower():
            return True
    
    return False


def verify_certificate_chain(
    certificate: x509.Certificate,
    ca_certificate: x509.Certificate
) -> bool:
    """
    Verify certificate chain: check if certificate is signed by CA.
    
    Args:
        certificate: Certificate to verify
        ca_certificate: Root CA certificate
        
    Returns:
        True if certificate chain is valid, False otherwise
    """
    # Check if certificate is directly signed by CA
    if certificate.issuer == ca_certificate.subject:
        return verify_certificate_signature(certificate, ca_certificate)
    
    # For a simple PKI with only root CA, if issuer doesn't match, it's invalid
    return False


def validate_certificate(
    cert_data: bytes,
    ca_cert_path: Path,
    expected_hostname: Optional[str] = None,
    current_time: Optional[datetime] = None
) -> x509.Certificate:
    """
    Comprehensive certificate validation.
    
    This function performs all necessary checks:
    1. Load and parse certificate
    2. Check if self-signed (reject if so)
    3. Check validity period (not expired, not before valid date)
    4. Verify signature chain (signed by trusted CA)
    5. Check hostname match (if expected_hostname provided)
    
    Args:
        cert_data: Certificate data in PEM or DER format
        ca_cert_path: Path to CA certificate file
        expected_hostname: Expected hostname/CN (optional)
        current_time: Current time for validity check (default: UTC now)
        
    Returns:
        Validated certificate object
        
    Raises:
        BadCertificateError: If validation fails with reason
    """
    if current_time is None:
        current_time = datetime.utcnow()
    
    # Load certificate
    try:
        certificate = load_certificate(cert_data)
    except ValueError as e:
        raise BadCertificateError(f"Invalid certificate format: {e}")
    
    # Check if self-signed (reject self-signed certificates)
    if is_self_signed(certificate):
        raise BadCertificateError("Self-signed certificate rejected")
    
    # Check validity period
    if not check_certificate_validity(certificate, current_time):
        if current_time < certificate.not_valid_before:
            raise BadCertificateError(
                f"Certificate not yet valid (valid from: {certificate.not_valid_before})"
            )
        else:
            raise BadCertificateError(
                f"Certificate expired (expired on: {certificate.not_valid_after})"
            )
    
    # Load CA certificate
    try:
        ca_certificate = load_ca_certificate(ca_cert_path)
    except FileNotFoundError as e:
        raise BadCertificateError(f"CA certificate not found: {e}")
    except ValueError as e:
        raise BadCertificateError(f"Invalid CA certificate: {e}")
    
    # Verify certificate chain (signed by CA)
    if not verify_certificate_chain(certificate, ca_certificate):
        raise BadCertificateError(
            "Certificate not signed by trusted CA or signature verification failed"
        )
    
    # Check hostname match if expected_hostname is provided
    if expected_hostname:
        if not check_hostname_match(certificate, expected_hostname):
            cn = get_certificate_cn(certificate)
            san_dns = get_certificate_san_dns_names(certificate)
            raise BadCertificateError(
                f"Hostname mismatch: expected '{expected_hostname}', "
                f"got CN='{cn}', SAN={san_dns}"
            )
    
    return certificate


def pki_connect(
    cert_data: bytes,
    ca_cert_path: Path,
    expected_hostname: Optional[str] = None
):
    """
    PKI_CONNECT: Validate peer certificate during connection establishment.
    
    This is the main function for certificate validation during the connection phase.
    It validates the peer's certificate and returns the certificate along with a status.
    
    Args:
        cert_data: Peer's certificate data in PEM or DER format
        ca_cert_path: Path to CA certificate file
        expected_hostname: Expected hostname/CN (optional)
        
    Returns:
        Tuple of (certificate, status) where status is "OK" or error message starting with "BAD_CERT:"
        
    Note:
        This function returns a status string instead of raising exceptions
        to allow for easier integration with protocol handlers.
    """
    try:
        certificate = validate_certificate(
            cert_data=cert_data,
            ca_cert_path=ca_cert_path,
            expected_hostname=expected_hostname
        )
        return certificate, "OK"
    except BadCertificateError as e:
        return None, str(e)  # Returns "BAD_CERT: <reason>"
    except Exception as e:
        return None, f"BAD_CERT: Unexpected error: {e}"


def cert_verify(
    certificate: x509.Certificate,
    ca_cert_path: Path,
    expected_hostname: Optional[str] = None,
    current_time: Optional[datetime] = None
):
    """
    CERT_VERIFY: Verify a certificate object (already loaded).
    
    This function verifies a certificate that has already been loaded into memory.
    Useful for re-verification or when certificate is already parsed.
    
    Args:
        certificate: Certificate object to verify
        ca_cert_path: Path to CA certificate file
        expected_hostname: Expected hostname/CN (optional)
        current_time: Current time for validity check (default: UTC now)
        
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if certificate is valid, False otherwise
        - error_message: None if valid, "BAD_CERT: <reason>" if invalid
    """
    if current_time is None:
        current_time = datetime.utcnow()
    
    try:
        # Check if self-signed
        if is_self_signed(certificate):
            return False, "BAD_CERT: Self-signed certificate rejected"
        
        # Check validity period
        if not check_certificate_validity(certificate, current_time):
            if current_time < certificate.not_valid_before:
                return False, f"BAD_CERT: Certificate not yet valid (valid from: {certificate.not_valid_before})"
            else:
                return False, f"BAD_CERT: Certificate expired (expired on: {certificate.not_valid_after})"
        
        # Load and verify CA certificate
        try:
            ca_certificate = load_ca_certificate(ca_cert_path)
        except FileNotFoundError as e:
            return False, f"BAD_CERT: CA certificate not found: {e}"
        except ValueError as e:
            return False, f"BAD_CERT: Invalid CA certificate: {e}"
        
        # Verify certificate chain
        if not verify_certificate_chain(certificate, ca_certificate):
            return False, "BAD_CERT: Certificate not signed by trusted CA or signature verification failed"
        
        # Check hostname match if expected_hostname is provided
        if expected_hostname:
            if not check_hostname_match(certificate, expected_hostname):
                cn = get_certificate_cn(certificate)
                san_dns = get_certificate_san_dns_names(certificate)
                return False, (
                    f"BAD_CERT: Hostname mismatch: expected '{expected_hostname}', "
                    f"got CN='{cn}', SAN={san_dns}"
                )
        
        return True, None
        
    except Exception as e:
        return False, f"BAD_CERT: Unexpected error: {e}"
