"""Create Root CA (RSA + self-signed X.509) using cryptography."""
import argparse
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_ca(name: str, key_size: int = 2048, validity_days: int = 3650):
    """
    Generate a root Certificate Authority (CA) private key and self-signed certificate.
    
    Args:
        name: Common Name (CN) for the CA certificate
        key_size: RSA key size in bits (default: 2048)
        validity_days: Certificate validity period in days (default: 3650 = 10 years)
    
    Returns:
        tuple: (private_key, certificate)
    """
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    
    # Get public key from private key
    public_key = private_key.public_key()
    
    # Create certificate subject (same as issuer for self-signed CA)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    # Set validity period
    now = datetime.utcnow()
    valid_from = now
    valid_to = now + timedelta(days=validity_days)
    
    # Build the certificate
    cert = x509.CertificateBuilder().subject_name(
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
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    return private_key, cert


def save_ca_files(private_key, certificate, output_dir: Path):
    """
    Save CA private key and certificate to files.
    
    Args:
        private_key: RSA private key object
        certificate: X.509 certificate object
        output_dir: Directory to save files to
    """
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save private key (PEM format, encrypted with no password for simplicity)
    key_path = output_dir / "ca_key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✓ CA private key saved to: {key_path}")
    
    # Save certificate (PEM format)
    cert_path = output_dir / "ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"✓ CA certificate saved to: {cert_path}")
    
    # Print certificate details
    print(f"\nCertificate Details:")
    print(f"  Subject: {certificate.subject}")
    print(f"  Issuer: {certificate.issuer}")
    print(f"  Serial Number: {certificate.serial_number}")
    print(f"  Valid From: {certificate.not_valid_before}")
    print(f"  Valid To: {certificate.not_valid_after}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a root Certificate Authority (CA) private key and self-signed certificate"
    )
    parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="Common Name (CN) for the CA certificate (e.g., 'SaadAhmed Root CA')"
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default="certs",
        help="Output directory for CA files (default: certs)"
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
        default=3650,
        help="Certificate validity period in days (default: 3650 = 10 years)"
    )
    
    args = parser.parse_args()
    
    # Generate CA
    print(f"Generating Root CA: {args.name}")
    print(f"Key size: {args.key_size} bits")
    print(f"Validity: {args.validity_days} days\n")
    
    private_key, certificate = generate_ca(
        name=args.name,
        key_size=args.key_size,
        validity_days=args.validity_days
    )
    
    # Save files
    output_dir = Path(args.out_dir)
    save_ca_files(private_key, certificate, output_dir)
    
    print(f"\n✓ Root CA generation completed successfully!")


if __name__ == "__main__":
    main()
