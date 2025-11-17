"""Client implementation with certificate exchange, DH key exchange, and secure authentication."""
import json
import os
import socket
import sys
from pathlib import Path
from typing import Optional

from app.common.protocol import (
    Hello,
    ServerHello,
    DHClient,
    DHServer,
    Register,
    RegisterResponse,
    Login,
    LoginResponse,
    SessionKeyEstablished,
    Message,
    Receipt,
    ErrorResponse,
)
from app.common.utils import b64d, b64e
from app.crypto import auth, dh, message, pki, receipt
from app.storage import transcript


def load_client_certificate(cert_path: Path) -> bytes:
    """Load client certificate from file."""
    with open(cert_path, "rb") as f:
        return f.read()


def chat_loop(sock: socket.socket, session_key: bytes, client_key_path: Path, server_cert):
    """
    Chat loop: send and receive encrypted messages.
    
    Args:
        sock: Open socket connection to server
        session_key: AES-128 session key for encryption
        client_key_path: Path to client's private key for signing
        server_cert: Server's X.509 certificate
    """
    import threading
    import time
    
    # Create transcript file for this session
    transcripts_dir = Path("transcripts")
    server_cn = pki.get_certificate_cn(server_cert) or "unknown"
    session_id = f"client_{int(time.time())}_{server_cn}"
    transcript_path = transcripts_dir / f"{session_id}.txt"
    transcripts_dir.mkdir(parents=True, exist_ok=True)
    
    # Get server certificate fingerprint
    server_cert_fingerprint = transcript.get_certificate_fingerprint(server_cert)
    
    # Get client certificate fingerprint
    certs_dir = Path("certs")
    client_cert_path = certs_dir / "client_cert.pem"
    from cryptography import x509
    with open(client_cert_path, "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())
    client_cert_fingerprint = transcript.get_certificate_fingerprint(client_cert)
    
    seqno = 0
    expected_seqno = 0
    
    def receive_messages():
        """Thread function to receive messages from server."""
        nonlocal expected_seqno
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    print("\n✗ Server closed connection")
                    break
                
                try:
                    msg_json = json.loads(data.decode('utf-8'))
                    msg_type = msg_json.get('type')
                except Exception as e:
                    print(f"\n✗ Invalid message format: {e}")
                    continue
                
                if msg_type == "msg":
                    # Handle received chat message
                    try:
                        msg = Message.model_validate(msg_json)
                    except Exception as e:
                        print(f"\n✗ Invalid Message format: {e}")
                        continue
                    
                    # Load server certificate for verification
                    certs_dir = Path("certs")
                    ca_cert_path = certs_dir / "ca_cert.pem"
                    server_cert_path = certs_dir / "server_cert.pem"
                    
                    if not server_cert_path.exists():
                        print("\n✗ Server certificate not found")
                        continue
                    
                    from cryptography import x509
                    with open(server_cert_path, "rb") as f:
                        server_cert = x509.load_pem_x509_certificate(f.read())
                    
                    # Decrypt and verify message
                    success, plaintext, error_msg = message.decrypt_and_verify_message(
                        seqno=msg.seqno,
                        timestamp=msg.ts,
                        ciphertext_b64=msg.ct,
                        signature_b64=msg.sig,
                        session_key=session_key,
                        sender_certificate=server_cert,
                        expected_seqno=expected_seqno
                    )
                    
                    if success:
                        expected_seqno = msg.seqno
                        print(f"\n[Server] [{msg.seqno}]: {plaintext}")
                        
                        # Log to transcript: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
                        transcript.append_to_transcript(
                            transcript_path=transcript_path,
                            seqno=msg.seqno,
                            timestamp=msg.ts,
                            ciphertext_b64=msg.ct,
                            signature_b64=msg.sig,
                            peer_cert_fingerprint=server_cert_fingerprint
                        )
                    else:
                        print(f"\n✗ Message verification failed: {error_msg}")
                
                elif msg_type == "receipt":
                    # Handle server's session receipt
                    try:
                        server_receipt = Receipt.model_validate(msg_json)
                        
                        # Verify server's receipt
                        is_valid, error_msg = receipt.verify_session_receipt(
                            receipt=server_receipt,
                            transcript_path=transcript_path,
                            signer_certificate=server_cert
                        )
                        
                        if is_valid:
                            print(f"\n✓ Server receipt verified: seq {server_receipt.first_seq}-{server_receipt.last_seq}")
                            print(f"  Transcript hash: {server_receipt.transcript_sha256[:16]}...")
                            
                            # Save receipt to file
                            receipt_path = transcript_path.parent / f"{transcript_path.stem}_server_receipt.json"
                            with open(receipt_path, "w") as f:
                                f.write(server_receipt.model_dump_json(indent=2))
                        else:
                            print(f"\n✗ Server receipt verification failed: {error_msg}")
                    
                    except Exception as e:
                        print(f"\n✗ Error processing server receipt: {e}")
                        import traceback
                        traceback.print_exc()
                
                elif msg_type == "error":
                    error = ErrorResponse.model_validate(msg_json)
                    print(f"\n✗ Server error: {error.error}")
                    if error.error in ["REPLAY", "SIG_FAIL"]:
                        print("  Connection may be compromised, consider reconnecting")
            
            except socket.error:
                print("\n✗ Socket error, closing connection")
                break
            except Exception as e:
                print(f"\n✗ Error receiving message: {e}")
                break
    
    # Start receive thread
    receive_thread = threading.Thread(target=receive_messages, daemon=True)
    receive_thread.start()
    
    # Main send loop
    print("\n✓ Entering chat mode. Type messages and press Enter to send.")
    print("  Type 'quit' or 'exit' to disconnect.\n")
    
    try:
        while True:
            try:
                # Read input from console
                plaintext = input()
                
                if plaintext.lower() in ['quit', 'exit']:
                    print("Disconnecting...")
                    # Generate and send client receipt before disconnecting
                    client_receipt = receipt.generate_session_receipt(
                        transcript_path=transcript_path,
                        peer="client",
                        private_key_path=client_key_path
                    )
                    
                    if client_receipt:
                        sock.send(client_receipt.model_dump_json().encode('utf-8'))
                        print(f"✓ Client receipt sent: seq {client_receipt.first_seq}-{client_receipt.last_seq}")
                        print(f"  Transcript hash: {client_receipt.transcript_sha256[:16]}...")
                        
                        # Save receipt to file
                        receipt_path = transcript_path.parent / f"{transcript_path.stem}_client_receipt.json"
                        receipt.save_receipt(client_receipt, receipt_path)
                        print(f"✓ Client receipt saved to: {receipt_path}")
                    break
                
                if not plaintext.strip():
                    continue
                
                # Increment sequence number
                seqno += 1
                
                # Encrypt and sign message
                timestamp, ciphertext_b64, signature_b64 = message.encrypt_and_sign_message(
                    plaintext=plaintext,
                    seqno=seqno,
                    session_key=session_key,
                    private_key_path=client_key_path
                )
                
                # Create and send message
                msg = Message(
                    seqno=seqno,
                    ts=timestamp,
                    ct=ciphertext_b64,
                    sig=signature_b64
                )
                
                sock.send(msg.model_dump_json().encode('utf-8'))
                print(f"✓ Message [{seqno}] sent")
                
                # Log to transcript: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
                transcript.append_to_transcript(
                    transcript_path=transcript_path,
                    seqno=seqno,
                    timestamp=timestamp,
                    ciphertext_b64=ciphertext_b64,
                    signature_b64=signature_b64,
                    peer_cert_fingerprint=server_cert_fingerprint
                )
            
            except EOFError:
                # Handle Ctrl+D
                print("\nDisconnecting...")
                # Generate and send client receipt before disconnecting
                try:
                    client_receipt = receipt.generate_session_receipt(
                        transcript_path=transcript_path,
                        peer="client",
                        private_key_path=client_key_path
                    )
                    
                    if client_receipt:
                        sock.send(client_receipt.model_dump_json().encode('utf-8'))
                        print(f"✓ Client receipt sent: seq {client_receipt.first_seq}-{client_receipt.last_seq}")
                        
                        # Save receipt to file
                        receipt_path = transcript_path.parent / f"{transcript_path.stem}_client_receipt.json"
                        receipt.save_receipt(client_receipt, receipt_path)
                except:
                    pass
                break
            except KeyboardInterrupt:
                # Handle Ctrl+C
                print("\nDisconnecting...")
                # Generate and send client receipt before disconnecting
                try:
                    client_receipt = receipt.generate_session_receipt(
                        transcript_path=transcript_path,
                        peer="client",
                        private_key_path=client_key_path
                    )
                    
                    if client_receipt:
                        sock.send(client_receipt.model_dump_json().encode('utf-8'))
                        print(f"✓ Client receipt sent: seq {client_receipt.first_seq}-{client_receipt.last_seq}")
                        
                        # Save receipt to file
                        receipt_path = transcript_path.parent / f"{transcript_path.stem}_client_receipt.json"
                        receipt.save_receipt(client_receipt, receipt_path)
                except:
                    pass
                break
            except Exception as e:
                print(f"\n✗ Error sending message: {e}")
                import traceback
                traceback.print_exc()
    
    finally:
        sock.close()


def connect_and_authenticate(
    server_host: str,
    server_port: int,
    action: str,  # "register" or "login"
    email: Optional[str] = None,
    username: str = None,
    password: str = None,
) -> tuple[bool, Optional[bytes], Optional[socket.socket]]:
    """
    Connect to server, perform certificate exchange, DH key exchange, and authenticate.
    
    Args:
        server_host: Server hostname
        server_port: Server port
        action: "register" or "login"
        email: Email (required for registration)
        username: Username
        password: Password
        
    Returns:
        Tuple of (success, session_key, socket)
        - success: True if successful, False otherwise
        - session_key: Session key bytes if login successful, None otherwise
        - socket: Open socket if login successful (for chat), None otherwise
    """
    # Load client certificate
    certs_dir = Path("certs")
    client_cert_path = certs_dir / "client_cert.pem"
    ca_cert_path = certs_dir / "ca_cert.pem"
    
    if not client_cert_path.exists():
        print(f"✗ Client certificate not found: {client_cert_path}")
        return False, None, None
    
    if not ca_cert_path.exists():
        print(f"✗ CA certificate not found: {ca_cert_path}")
        return False, None, None
    
    client_cert_data = load_client_certificate(client_cert_path)
    client_cert_b64 = b64e(client_cert_data)
    
    # Connect to server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_host, server_port))
        print(f"✓ Connected to server {server_host}:{server_port}")
    except Exception as e:
        print(f"✗ Failed to connect to server: {e}")
        return False, None, None
    
    try:
        # Step 1: Send Hello with client certificate
        hello_msg = Hello(cert=client_cert_b64)
        sock.send(hello_msg.model_dump_json().encode('utf-8'))
        
        # Step 2: Receive ServerHello and validate server certificate
        data = sock.recv(4096)
        if not data:
            print("✗ Server closed connection")
            return False, None, None
        
        try:
            server_hello = ServerHello.model_validate_json(data.decode('utf-8'))
        except Exception as e:
            print(f"✗ Invalid ServerHello message: {e}")
            return False, None, None
        
        # Validate server certificate
        server_cert_data = b64d(server_hello.cert)
        server_cert, status = pki.pki_connect(
            cert_data=server_cert_data,
            ca_cert_path=ca_cert_path,
            expected_hostname=server_host  # Validate server hostname
        )
        
        if status != "OK":
            print(f"✗ Server certificate validation failed: {status}")
            return False, None, None
        
        print(f"✓ Server certificate validated: {pki.get_certificate_cn(server_cert)}")
        
        # Step 3: Generate client DH keypair and send DHClient
        client_dh_private, client_dh_public = dh.generate_dh_keypair()
        client_dh_pubkey_data = dh.serialize_public_key(client_dh_public)
        client_dh_pubkey_b64 = b64e(client_dh_pubkey_data)
        
        dh_client_msg = DHClient(dh_pubkey=client_dh_pubkey_b64)
        sock.send(dh_client_msg.model_dump_json().encode('utf-8'))
        
        # Step 4: Receive DHServer
        data = sock.recv(4096)
        if not data:
            print("✗ Server closed connection")
            return False, None, None
        
        try:
            dh_server_msg = DHServer.model_validate_json(data.decode('utf-8'))
        except Exception as e:
            print(f"✗ Invalid DHServer message: {e}")
            return False, None, None
        
        # Deserialize server's DH public key
        server_dh_pubkey_data = b64d(dh_server_msg.dh_pubkey)
        server_dh_pubkey = dh.deserialize_public_key(server_dh_pubkey_data)
        
        # Step 5: Compute shared secret and derive AES key
        shared_secret = dh.compute_shared_secret(client_dh_private, server_dh_pubkey)
        aes_key = dh.derive_aes_key(shared_secret)
        print(f"✓ AES key derived from DH exchange")
        
        # Step 6: Send Register or Login with encrypted data
        if action == "register":
            if not email or not username or not password:
                print("✗ Registration requires email, username, and password")
                return False, None, None
            
            encrypted_data = auth.encrypt_registration_payload(
                email=email,
                username=username,
                password=password,
                aes_key=aes_key
            )
            
            register_msg = Register(encrypted_data=encrypted_data)
            sock.send(register_msg.model_dump_json().encode('utf-8'))
            
            # Receive response
            data = sock.recv(4096)
            if not data:
                print("✗ Server closed connection")
                sock.close()
                return False, None, None
            
            try:
                response = RegisterResponse.model_validate_json(data.decode('utf-8'))
            except Exception as e:
                # Try ErrorResponse
                try:
                    error = ErrorResponse.model_validate_json(data.decode('utf-8'))
                    print(f"✗ Server error: {error.error}")
                    sock.close()
                    return False, None, None
                except:
                    print(f"✗ Invalid response: {e}")
                    sock.close()
                    return False, None, None
            
            if response.status == "OK":
                print(f"✓ Registration successful")
                sock.close()
                return True, None, None
            else:
                print(f"✗ Registration failed: {response.status}")
                sock.close()
                return False, None, None
        
        elif action == "login":
            if not username or not password:
                print("✗ Login requires username and password")
                return False, None, None
            
            encrypted_data = auth.encrypt_login_payload(
                username=username,
                password=password,
                aes_key=aes_key
            )
            
            login_msg = Login(encrypted_data=encrypted_data)
            sock.send(login_msg.model_dump_json().encode('utf-8'))
            
            # Receive response
            data = sock.recv(4096)
            if not data:
                print("✗ Server closed connection")
                sock.close()
                return False, None, None
            
            try:
                response = LoginResponse.model_validate_json(data.decode('utf-8'))
            except Exception as e:
                # Try ErrorResponse
                try:
                    error = ErrorResponse.model_validate_json(data.decode('utf-8'))
                    print(f"✗ Server error: {error.error}")
                    sock.close()
                    return False, None, None
                except:
                    print(f"✗ Invalid response: {e}")
                    sock.close()
                    return False, None, None
            
            if response.status == "OK":
                print(f"✓ Login successful")
                
                # Step 7: Establish session key for chat messages (new DH exchange)
                print(f"→ Establishing session key for chat...")
                
                # Generate client session DH keypair
                client_session_dh_private, client_session_dh_public = dh.generate_dh_keypair()
                client_session_dh_pubkey_data = dh.serialize_public_key(client_session_dh_public)
                client_session_dh_pubkey_b64 = b64e(client_session_dh_pubkey_data)
                
                # Send client's session DH public key
                session_dh_client_msg = DHClient(dh_pubkey=client_session_dh_pubkey_b64)
                sock.send(session_dh_client_msg.model_dump_json().encode('utf-8'))
                
                # Receive server's session DH public key
                data = sock.recv(4096)
                if not data:
                    print("✗ Server closed connection during session key establishment")
                    sock.close()
                    return False, None, None
                
                try:
                    session_dh_server_msg = DHServer.model_validate_json(data.decode('utf-8'))
                except Exception as e:
                    print(f"✗ Invalid SessionDHServer message: {e}")
                    sock.close()
                    return False, None, None
                
                # Deserialize server's session DH public key
                server_session_dh_pubkey_data = b64d(session_dh_server_msg.dh_pubkey)
                server_session_dh_pubkey = dh.deserialize_public_key(server_session_dh_pubkey_data)
                
                # Compute session key: K = Trunc16(SHA256(big-endian(Ks)))
                session_shared_secret = dh.compute_shared_secret(
                    client_session_dh_private,
                    server_session_dh_pubkey
                )
                session_key = dh.derive_aes_key(session_shared_secret)
                print(f"✓ Session key established: {session_key.hex()[:16]}...")
                
                # Receive confirmation
                data = sock.recv(4096)
                if not data:
                    print("✗ Server closed connection")
                    sock.close()
                    return False, None, None
                
                try:
                    confirmation = SessionKeyEstablished.model_validate_json(data.decode('utf-8'))
                except Exception as e:
                    print(f"✗ Invalid SessionKeyEstablished message: {e}")
                    sock.close()
                    return False, None, None
                
                if confirmation.status == "OK":
                    print(f"✓ Session established. Ready for chat messages.")
                    # Return success with session key and open socket
                    return True, session_key, sock
                else:
                    print(f"✗ Session key establishment failed: {confirmation.status}")
                    sock.close()
                    return False, None, None
            else:
                print(f"✗ Login failed: {response.status}")
                sock.close()
                return False, None, None
        else:
            print(f"✗ Unknown action: {action}")
            return False, None, None
    
    except Exception as e:
        print(f"✗ Error during authentication: {e}")
        import traceback
        traceback.print_exc()
        if sock:
            sock.close()
        return False, None, None


def main():
    """Main client entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure chat client")
    parser.add_argument(
        '--host',
        type=str,
        default=os.getenv('SERVER_HOST', 'localhost'),
        help='Server hostname (default: localhost)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=int(os.getenv('SERVER_PORT', 8888)),
        help='Server port (default: 8888)'
    )
    parser.add_argument(
        '--action',
        type=str,
        choices=['register', 'login'],
        required=True,
        help='Action to perform: register or login'
    )
    parser.add_argument(
        '--email',
        type=str,
        help='Email address (required for registration)'
    )
    parser.add_argument(
        '--username',
        type=str,
        required=True,
        help='Username'
    )
    parser.add_argument(
        '--password',
        type=str,
        required=True,
        help='Password'
    )
    
    args = parser.parse_args()
    
    if args.action == "register" and not args.email:
        print("✗ Email is required for registration")
        sys.exit(1)
    
    success, session_key, sock = connect_and_authenticate(
        server_host=args.host,
        server_port=args.port,
        action=args.action,
        email=args.email,
        username=args.username,
        password=args.password,
    )
    
    if success and args.action == "login" and session_key is not None:
        print(f"\n✓ Authentication and session key establishment complete")
        print(f"  Session key: {session_key.hex()[:16]}...")
        
        # Enter chat mode
        certs_dir = Path("certs")
        client_key_path = certs_dir / "client_key.pem"
        
        if not client_key_path.exists():
            print(f"✗ Client private key not found: {client_key_path}")
            if sock:
                sock.close()
            sys.exit(1)
        
        # Start chat loop
        chat_loop(sock, session_key, client_key_path)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
