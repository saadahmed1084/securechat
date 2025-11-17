"""Server implementation with certificate exchange, DH key exchange, and secure authentication."""
import json
import os
import socket
from pathlib import Path

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


def load_server_certificate(cert_path: Path) -> bytes:
    """Load server certificate from file."""
    with open(cert_path, "rb") as f:
        return f.read()


def handle_client_connection(client_socket: socket.socket, client_address: tuple):
    """Handle a single client connection with full authentication workflow."""
    try:
        # Load server certificate
        certs_dir = Path("certs")
        server_cert_path = certs_dir / "server_cert.pem"
        ca_cert_path = certs_dir / "ca_cert.pem"
        
        if not server_cert_path.exists():
            print(f"✗ Server certificate not found: {server_cert_path}")
            return
        
        if not ca_cert_path.exists():
            print(f"✗ CA certificate not found: {ca_cert_path}")
            return
        
        server_cert_data = load_server_certificate(server_cert_path)
        server_cert_b64 = b64e(server_cert_data)
        
        # Step 1: Receive Hello from client
        data = client_socket.recv(4096)
        if not data:
            return
        
        try:
            hello_msg = Hello.model_validate_json(data.decode('utf-8'))
        except Exception as e:
            print(f"✗ Invalid Hello message: {e}")
            error = ErrorResponse(error="INVALID_MESSAGE")
            client_socket.send(error.model_dump_json().encode('utf-8'))
            return
        
        # Step 2: Validate client certificate
        client_cert_data = b64d(hello_msg.cert)
        client_cert, status = pki.pki_connect(
            cert_data=client_cert_data,
            ca_cert_path=ca_cert_path,
            expected_hostname=None  # Server doesn't validate hostname for client certs
        )
        
        if status != "OK":
            print(f"✗ Client certificate validation failed: {status}")
            error = ErrorResponse(error=status)
            client_socket.send(error.model_dump_json().encode('utf-8'))
            return
        
        print(f"✓ Client certificate validated: {pki.get_certificate_cn(client_cert)}")
        
        # Step 3: Send ServerHello with server certificate
        server_hello = ServerHello(cert=server_cert_b64)
        client_socket.send(server_hello.model_dump_json().encode('utf-8'))
        
        # Step 4: Receive DHClient (client's DH public key)
        data = client_socket.recv(4096)
        if not data:
            return
        
        try:
            dh_client_msg = DHClient.model_validate_json(data.decode('utf-8'))
        except Exception as e:
            print(f"✗ Invalid DHClient message: {e}")
            error = ErrorResponse(error="INVALID_MESSAGE")
            client_socket.send(error.model_dump_json().encode('utf-8'))
            return
        
        # Deserialize client's DH public key
        client_dh_pubkey_data = b64d(dh_client_msg.dh_pubkey)
        client_dh_pubkey = dh.deserialize_public_key(client_dh_pubkey_data)
        
        # Step 5: Generate server DH keypair and send DHServer
        server_dh_private, server_dh_public = dh.generate_dh_keypair()
        server_dh_pubkey_data = dh.serialize_public_key(server_dh_public)
        server_dh_pubkey_b64 = b64e(server_dh_pubkey_data)
        
        dh_server_msg = DHServer(dh_pubkey=server_dh_pubkey_b64)
        client_socket.send(dh_server_msg.model_dump_json().encode('utf-8'))
        
        # Step 6: Compute shared secret and derive AES key
        shared_secret = dh.compute_shared_secret(server_dh_private, client_dh_pubkey)
        aes_key = dh.derive_aes_key(shared_secret)
        print(f"✓ AES key derived from DH exchange")
        
        # Step 7: Receive Register or Login
        data = client_socket.recv(4096)
        if not data:
            return
        
        try:
            message = json.loads(data.decode('utf-8'))
            msg_type = message.get('type')
        except Exception as e:
            print(f"✗ Invalid message format: {e}")
            error = ErrorResponse(error="INVALID_MESSAGE")
            client_socket.send(error.model_dump_json().encode('utf-8'))
            return
        
        if msg_type == "register":
            # Handle registration
            try:
                register_msg = Register.model_validate(message)
            except Exception as e:
                print(f"✗ Invalid Register message: {e}")
                error = ErrorResponse(error="INVALID_MESSAGE")
                client_socket.send(error.model_dump_json().encode('utf-8'))
                return
            
            # Verify client certificate is still valid (required for login)
            # For registration, we already validated it, but we should verify it again
            # to ensure it hasn't been revoked or expired
            is_valid, error_msg = pki.cert_verify(
                certificate=client_cert,
                ca_cert_path=ca_cert_path,
                expected_hostname=None
            )
            
            if not is_valid:
                print(f"✗ Client certificate invalid during registration: {error_msg}")
                error = ErrorResponse(error=error_msg)
                client_socket.send(error.model_dump_json().encode('utf-8'))
                return
            
            # Decrypt and register user
            success, message = auth.handle_secure_registration(
                encrypted_payload=register_msg.encrypted_data,
                aes_key=aes_key
            )
            
            if success:
                print(f"✓ User registered successfully")
                response = RegisterResponse(status="OK")
            else:
                print(f"✗ Registration failed: {message}")
                response = RegisterResponse(status=message)
            
            client_socket.send(response.model_dump_json().encode('utf-8'))
            
        elif msg_type == "login":
            # Handle login
            try:
                login_msg = Login.model_validate(message)
            except Exception as e:
                print(f"✗ Invalid Login message: {e}")
                error = ErrorResponse(error="INVALID_MESSAGE")
                client_socket.send(error.model_dump_json().encode('utf-8'))
                return
            
            # Verify client certificate is valid and trusted (required for login)
            is_valid, error_msg = pki.cert_verify(
                certificate=client_cert,
                ca_cert_path=ca_cert_path,
                expected_hostname=None
            )
            
            if not is_valid:
                print(f"✗ Client certificate invalid during login: {error_msg}")
                error = ErrorResponse(error=error_msg)
                client_socket.send(error.model_dump_json().encode('utf-8'))
                return
            
            # Decrypt and verify credentials
            success, message = auth.handle_secure_login(
                encrypted_payload=login_msg.encrypted_data,
                aes_key=aes_key
            )
            
            if success:
                print(f"✓ User logged in successfully")
                response = LoginResponse(status="OK")
                client_socket.send(response.model_dump_json().encode('utf-8'))
                
                # Step 8: Establish session key for chat messages (new DH exchange)
                print(f"→ Establishing session key for chat...")
                
                # Receive client's session DH public key
                data = client_socket.recv(4096)
                if not data:
                    print("✗ Client closed connection during session key establishment")
                    return
                
                try:
                    session_dh_client_msg = DHClient.model_validate_json(data.decode('utf-8'))
                except Exception as e:
                    print(f"✗ Invalid SessionDHClient message: {e}")
                    error = ErrorResponse(error="INVALID_MESSAGE")
                    client_socket.send(error.model_dump_json().encode('utf-8'))
                    return
                
                # Deserialize client's session DH public key
                client_session_dh_pubkey_data = b64d(session_dh_client_msg.dh_pubkey)
                client_session_dh_pubkey = dh.deserialize_public_key(client_session_dh_pubkey_data)
                
                # Generate server session DH keypair
                server_session_dh_private, server_session_dh_public = dh.generate_dh_keypair()
                server_session_dh_pubkey_data = dh.serialize_public_key(server_session_dh_public)
                server_session_dh_pubkey_b64 = b64e(server_session_dh_pubkey_data)
                
                # Send server's session DH public key
                session_dh_server_msg = DHServer(dh_pubkey=server_session_dh_pubkey_b64)
                client_socket.send(session_dh_server_msg.model_dump_json().encode('utf-8'))
                
                # Compute session key: K = Trunc16(SHA256(big-endian(Ks)))
                session_shared_secret = dh.compute_shared_secret(
                    server_session_dh_private, 
                    client_session_dh_pubkey
                )
                session_key = dh.derive_aes_key(session_shared_secret)
                print(f"✓ Session key established: {session_key.hex()[:16]}...")
                
                # Send confirmation
                confirmation = SessionKeyEstablished(status="OK")
                client_socket.send(confirmation.model_dump_json().encode('utf-8'))
                
                # Store session key for chat message encryption
                # Enter chat message handling loop
                print(f"✓ Session established. Ready for chat messages.")
                
                # Create transcript file for this session
                transcripts_dir = Path("transcripts")
                client_cn = pki.get_certificate_cn(client_cert) or "unknown"
                import time
                session_id = f"server_{int(time.time())}_{client_cn}"
                transcript_path = transcripts_dir / f"{session_id}.txt"
                transcripts_dir.mkdir(parents=True, exist_ok=True)
                
                # Get client certificate fingerprint
                client_cert_fingerprint = transcript.get_certificate_fingerprint(client_cert)
                
                # Track sequence numbers for replay protection
                expected_seqno = 0
                
                # Chat message loop
                while True:
                    try:
                        data = client_socket.recv(4096)
                        if not data:
                            print("✗ Client closed connection")
                            break
                        
                        try:
                            msg_json = json.loads(data.decode('utf-8'))
                            msg_type = msg_json.get('type')
                        except Exception as e:
                            print(f"✗ Invalid message format: {e}")
                            error = ErrorResponse(error="INVALID_MESSAGE")
                            client_socket.send(error.model_dump_json().encode('utf-8'))
                            continue
                        
                        if msg_type == "msg":
                            # Handle chat message
                            try:
                                msg = Message.model_validate(msg_json)
                            except Exception as e:
                                print(f"✗ Invalid Message format: {e}")
                                error = ErrorResponse(error="INVALID_MESSAGE")
                                client_socket.send(error.model_dump_json().encode('utf-8'))
                                continue
                            
                            # Decrypt and verify message
                            success, plaintext, error_msg = message.decrypt_and_verify_message(
                                seqno=msg.seqno,
                                timestamp=msg.ts,
                                ciphertext_b64=msg.ct,
                                signature_b64=msg.sig,
                                session_key=session_key,
                                sender_certificate=client_cert,
                                expected_seqno=expected_seqno
                            )
                            
                            if success:
                                expected_seqno = msg.seqno
                                print(f"✓ Message [{msg.seqno}] from {pki.get_certificate_cn(client_cert)}: {plaintext}")
                                
                                # Log to transcript: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
                                transcript.append_to_transcript(
                                    transcript_path=transcript_path,
                                    seqno=msg.seqno,
                                    timestamp=msg.ts,
                                    ciphertext_b64=msg.ct,
                                    signature_b64=msg.sig,
                                    peer_cert_fingerprint=client_cert_fingerprint
                                )
                            else:
                                print(f"✗ Message verification failed: {error_msg}")
                                # Send error response
                                if error_msg.startswith("REPLAY"):
                                    error = ErrorResponse(error="REPLAY")
                                elif error_msg.startswith("SIG_FAIL"):
                                    error = ErrorResponse(error="SIG_FAIL")
                                else:
                                    error = ErrorResponse(error="INVALID_MESSAGE")
                                client_socket.send(error.model_dump_json().encode('utf-8'))
                                # Continue to receive next message
                                continue
                        
                        elif msg_type == "receipt":
                            # Handle client's session receipt
                            try:
                                client_receipt = Receipt.model_validate(msg_json)
                                
                                # Verify client's receipt
                                is_valid, error_msg = receipt.verify_session_receipt(
                                    receipt=client_receipt,
                                    transcript_path=transcript_path,
                                    signer_certificate=client_cert
                                )
                                
                                if is_valid:
                                    print(f"✓ Client receipt verified: seq {client_receipt.first_seq}-{client_receipt.last_seq}")
                                    print(f"  Transcript hash: {client_receipt.transcript_sha256[:16]}...")
                                    
                                    # Save client receipt to file
                                    client_receipt_path = transcript_path.parent / f"{transcript_path.stem}_client_receipt.json"
                                    receipt.save_receipt(client_receipt, client_receipt_path)
                                    print(f"✓ Client receipt saved to: {client_receipt_path}")
                                else:
                                    print(f"✗ Client receipt verification failed: {error_msg}")
                                
                                # Generate and send server's receipt
                                certs_dir = Path("certs")
                                server_key_path = certs_dir / "server_key.pem"
                                
                                if server_key_path.exists():
                                    server_receipt = receipt.generate_session_receipt(
                                        transcript_path=transcript_path,
                                        peer="server",
                                        private_key_path=server_key_path
                                    )
                                    
                                    if server_receipt:
                                        client_socket.send(server_receipt.model_dump_json().encode('utf-8'))
                                        print(f"✓ Server receipt sent: seq {server_receipt.first_seq}-{server_receipt.last_seq}")
                                        print(f"  Transcript hash: {server_receipt.transcript_sha256[:16]}...")
                                        
                                        # Save receipt to file
                                        receipt_path = transcript_path.parent / f"{transcript_path.stem}_server_receipt.json"
                                        receipt.save_receipt(server_receipt, receipt_path)
                                        print(f"✓ Server receipt saved to: {receipt_path}")
                                
                                # Session closure complete
                                break
                            
                            except Exception as e:
                                print(f"✗ Error processing receipt: {e}")
                                import traceback
                                traceback.print_exc()
                                break
                        
                        else:
                            print(f"✗ Unknown message type after login: {msg_type}")
                            error = ErrorResponse(error="INVALID_MESSAGE")
                            client_socket.send(error.model_dump_json().encode('utf-8'))
                    
                    except socket.error:
                        print("✗ Socket error, closing connection")
                        break
                    except Exception as e:
                        print(f"✗ Error processing chat message: {e}")
                        import traceback
                        traceback.print_exc()
                        error = ErrorResponse(error="INTERNAL_ERROR")
                        try:
                            client_socket.send(error.model_dump_json().encode('utf-8'))
                        except:
                            pass
                        break
                
                # Generate receipt on session closure (if transcript exists and no receipt was sent)
                if transcript_path and transcript_path.exists():
                    certs_dir = Path("certs")
                    server_key_path = certs_dir / "server_key.pem"
                    
                    if server_key_path.exists():
                        server_receipt = receipt.generate_session_receipt(
                            transcript_path=transcript_path,
                            peer_name="server",
                            private_key_path=server_key_path
                        )
                        
                        if server_receipt:
                            print(f"\n✓ Session receipt generated:")
                            print(f"  Peer: {server_receipt.peer}")
                            print(f"  Sequence range: {server_receipt.first_seq}-{server_receipt.last_seq}")
                            print(f"  Transcript hash: {server_receipt.transcript_sha256}")
                            
                            # Save receipt to file
                            receipt_path = transcript_path.parent / f"{transcript_path.stem}_server_receipt.json"
                            with open(receipt_path, "w") as f:
                                f.write(server_receipt.model_dump_json(indent=2))
                            print(f"  Receipt saved to: {receipt_path}")
                
            else:
                print(f"✗ Login failed: {message}")
                response = LoginResponse(status=message)
                client_socket.send(response.model_dump_json().encode('utf-8'))
        else:
            print(f"✗ Unknown message type: {msg_type}")
            error = ErrorResponse(error="INVALID_MESSAGE")
            client_socket.send(error.model_dump_json().encode('utf-8'))
    
    except Exception as e:
        print(f"✗ Error handling client connection: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client_socket.close()


def main():
    """Main server entry point."""
    # Initialize database
    from app.storage import db
    try:
        db.init_database()
    except Exception as e:
        print(f"✗ Failed to initialize database: {e}")
        return
    
    # Server configuration
    host = os.getenv('SERVER_HOST', 'localhost')
    port = int(os.getenv('SERVER_PORT', 8888))
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"✓ Server listening on {host}:{port}")
        print(f"  Waiting for client connections...")
        
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"\n→ Client connected from {client_address}")
            handle_client_connection(client_socket, client_address)
    
    except KeyboardInterrupt:
        print("\n✓ Server shutting down...")
    except Exception as e:
        print(f"✗ Server error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
