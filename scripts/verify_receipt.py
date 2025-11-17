"""Offline receipt verification script."""
import argparse
from pathlib import Path

from app.crypto import receipt


def main():
    """Main entry point for offline receipt verification."""
    parser = argparse.ArgumentParser(
        description="Verify a session receipt offline for non-repudiation"
    )
    parser.add_argument(
        '--receipt',
        type=str,
        required=True,
        help='Path to receipt JSON file'
    )
    parser.add_argument(
        '--transcript',
        type=str,
        required=True,
        help='Path to transcript file'
    )
    parser.add_argument(
        '--cert',
        type=str,
        required=True,
        help='Path to signer\'s certificate file'
    )
    
    args = parser.parse_args()
    
    receipt_path = Path(args.receipt)
    transcript_path = Path(args.transcript)
    cert_path = Path(args.cert)
    
    # Verify receipt
    is_valid, error_msg = receipt.verify_receipt_offline(
        receipt_path=receipt_path,
        transcript_path=transcript_path,
        signer_cert_path=cert_path
    )
    
    if is_valid:
        print("✓ Receipt verification successful")
        print("  The receipt is valid and the transcript has not been modified.")
        print("  This provides non-repudiation evidence.")
        return 0
    else:
        print("✗ Receipt verification failed")
        print(f"  Error: {error_msg}")
        print("  The receipt may be invalid or the transcript may have been modified.")
        return 1


if __name__ == "__main__":
    exit(main())

