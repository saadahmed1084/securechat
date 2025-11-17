"""Client implementation with certificate exchange, DH key exchange, and secure authentication."""
import json
import os
import socket
import sys
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
    ErrorResponse,
)
from app.common.utils import b64d, b64e
from app.crypto import auth, dh, pki


def load_client_certificate(cert_path: Path) -> bytes:
    """Load client certificate from file."""
    with open(cert_path, "rb") as f:
        return f.read()


def connect_and_authenticate(
    server_host: str,
    server_port: int,
    action: str,  # "register" or "login"
    email: Optional[str] = None,
    username: str = None,
    password: str = None,
) -> bool:
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
        True if successful, False otherwise
    """
    # Load client certificate
    certs_dir = Path("certs")
    client_cert_path = certs_dir / "client_cert.pem"
    ca_cert_path = certs_dir / "ca_cert.pem"
    
    if not client_cert_path.exists():
        print(f"✗ Client certificate not found: {client_cert_path}")
        return False
    
    if not ca_cert_path.exists():
        print(f"✗ CA certificate not found: {ca_cert_path}")
        return False
    
    client_cert_data = load_client_certificate(client_cert_path)
    client_cert_b64 = b64e(client_cert_data)
    
    # Connect to server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_host, server_port))
        print(f"✓ Connected to server {server_host}:{server_port}")
    except Exception as e:
        print(f"✗ Failed to connect to server: {e}")
        return False
    
    try:
        # Step 1: Send Hello with client certificate
        hello_msg = Hello(cert=client_cert_b64)
        sock.send(hello_msg.model_dump_json().encode('utf-8'))
        
        # Step 2: Receive ServerHello and validate server certificate
        data = sock.recv(4096)
        if not data:
            print("✗ Server closed connection")
            return False
        
        try:
            server_hello = ServerHello.model_validate_json(data.decode('utf-8'))
        except Exception as e:
            print(f"✗ Invalid ServerHello message: {e}")
            return False
        
        # Validate server certificate
        server_cert_data = b64d(server_hello.cert)
        server_cert, status = pki.pki_connect(
            cert_data=server_cert_data,
            ca_cert_path=ca_cert_path,
            expected_hostname=server_host  # Validate server hostname
        )
        
        if status != "OK":
            print(f"✗ Server certificate validation failed: {status}")
            return False
        
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
            return False
        
        try:
            dh_server_msg = DHServer.model_validate_json(data.decode('utf-8'))
        except Exception as e:
            print(f"✗ Invalid DHServer message: {e}")
            return False
        
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
                return False
            
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
                return False
            
            try:
                response = RegisterResponse.model_validate_json(data.decode('utf-8'))
            except Exception as e:
                # Try ErrorResponse
                try:
                    error = ErrorResponse.model_validate_json(data.decode('utf-8'))
                    print(f"✗ Server error: {error.error}")
                    return False
                except:
                    print(f"✗ Invalid response: {e}")
                    return False
            
            if response.status == "OK":
                print(f"✓ Registration successful")
                return True
            else:
                print(f"✗ Registration failed: {response.status}")
                return False
        
        elif action == "login":
            if not username or not password:
                print("✗ Login requires username and password")
                return False
            
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
                return False
            
            try:
                response = LoginResponse.model_validate_json(data.decode('utf-8'))
            except Exception as e:
                # Try ErrorResponse
                try:
                    error = ErrorResponse.model_validate_json(data.decode('utf-8'))
                    print(f"✗ Server error: {error.error}")
                    return False
                except:
                    print(f"✗ Invalid response: {e}")
                    return False
            
            if response.status == "OK":
                print(f"✓ Login successful")
                return True
            else:
                print(f"✗ Login failed: {response.status}")
                return False
        else:
            print(f"✗ Unknown action: {action}")
            return False
    
    except Exception as e:
        print(f"✗ Error during authentication: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sock.close()


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
    
    success = connect_and_authenticate(
        server_host=args.host,
        server_port=args.port,
        action=args.action,
        email=args.email,
        username=args.username,
        password=args.password,
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
