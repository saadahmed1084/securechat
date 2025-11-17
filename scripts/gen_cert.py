"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
import argparse
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID


def load_ca_files(ca_dir: Path):
    """
    Load CA private key and certificate from files.
    
    Args:
        ca_dir: Directory containing CA files
        
    Returns:
        tuple: (ca_private_key, ca_certificate)
    """
    ca_key_path = ca_dir / "ca_key.pem"
    ca_cert_path = ca_dir / "ca_cert.pem"
    
    if not ca_key_path.exists():
        raise FileNotFoundError(f"CA private key not found: {ca_key_path}")
    if not ca_cert_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
    
    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(f.read())
    
    return ca_private_key, ca_certificate


def generate_certificate(
    cn: str,
    ca_private_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    key_size: int = 2048,
    validity_days: int = 365
):
    """
    Generate an RSA keypair and X.509 certificate signed by the CA.
    
    Args:
        cn: Common Name (CN) for the certificate
        ca_private_key: CA's private key for signing
        ca_certificate: CA's certificate (for issuer information)
        key_size: RSA key size in bits (default: 2048)
        validity_days: Certificate validity period in days (default: 365)
    
    Returns:
        tuple: (private_key, certificate)
    """
    # Generate RSA private key for the entity
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    
    # Get public key from private key
    public_key = private_key.public_key()
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Get issuer from CA certificate
    issuer = ca_certificate.subject
    
    # Set validity period
    now = datetime.utcnow()
    valid_from = now
    valid_to = now + timedelta(days=validity_days)
    
    # Build the certificate builder
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),
        ]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )
    
    # Add AuthorityKeyIdentifier extension
    # Try to get from CA's SubjectKeyIdentifier, fallback to CA's public key
    try:
        ca_ski = ca_certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        aki_ext = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski)
    except x509.ExtensionNotFound:
        # Fallback: use CA's public key directly
        aki_ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_certificate.public_key()
        )
    
    # Add AuthorityKeyIdentifier and sign the certificate
    cert = cert_builder.add_extension(
        aki_ext,
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())
    
    return private_key, cert


def save_certificate_files(private_key, certificate, output_path: Path):
    """
    Save entity private key and certificate to files.
    
    Args:
        private_key: RSA private key object
        certificate: X.509 certificate object
        output_path: Base path for output files (without extension)
    """
    # Create output directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save private key (PEM format)
    # Use naming convention: {base}_key.pem (consistent with ca_key.pem)
    key_path = output_path.parent / f"{output_path.name}_key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✓ Private key saved to: {key_path}")
    
    # Save certificate (PEM format)
    # Use naming convention: {base}_cert.pem (consistent with ca_cert.pem)
    cert_path = output_path.parent / f"{output_path.name}_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"✓ Certificate saved to: {cert_path}")
    
    # Print certificate details
    print(f"\nCertificate Details:")
    print(f"  Subject: {certificate.subject}")
    print(f"  Issuer: {certificate.issuer}")
    print(f"  Serial Number: {certificate.serial_number}")
    print(f"  Valid From: {certificate.not_valid_before}")
    print(f"  Valid To: {certificate.not_valid_after}")
    
    # Print SAN if present
    try:
        san_ext = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        print(f"  Subject Alternative Name: {san_ext.value}")
    except x509.ExtensionNotFound:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Issue server/client certificate signed by Root CA"
    )
    parser.add_argument(
        "--cn",
        type=str,
        required=True,
        help="Common Name (CN) for the certificate (e.g., 'server.local' or 'client.local')"
    )
    parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output path prefix for certificate files (e.g., 'certs/server' or 'certs/client')"
    )
    parser.add_argument(
        "--ca-dir",
        type=str,
        default="certs",
        help="Directory containing CA files (default: certs)"
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=2048,
        choices=[2048, 3072, 4096],
        help="RSA key size in bits (default: 2048)"
    )
    parser.add_argument(
        "--validity-days",
        type=int,
        default=365,
        help="Certificate validity period in days (default: 365)"
    )
    
    args = parser.parse_args()
    
    # Load CA files
    ca_dir = Path(args.ca_dir)
    print(f"Loading CA from: {ca_dir}")
    try:
        ca_private_key, ca_certificate = load_ca_files(ca_dir)
        print(f"✓ CA loaded successfully")
        print(f"  CA Subject: {ca_certificate.subject}\n")
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        print(f"  Please generate the CA first using: python scripts/gen_ca.py --name 'SaadAhmed Root CA'")
        return 1
    
    # Generate certificate
    print(f"Generating certificate for: {args.cn}")
    print(f"Key size: {args.key_size} bits")
    print(f"Validity: {args.validity_days} days\n")
    
    private_key, certificate = generate_certificate(
        cn=args.cn,
        ca_private_key=ca_private_key,
        ca_certificate=ca_certificate,
        key_size=args.key_size,
        validity_days=args.validity_days
    )
    
    # Save files
    output_path = Path(args.out)
    save_certificate_files(private_key, certificate, output_path)
    
    print(f"\n✓ Certificate generation completed successfully!")
    return 0


if __name__ == "__main__":
    exit(main())
