from cryptography.hazmat.primitives import serialization
from TLS.DigitalSigniture import DigitalSignature
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.OpenSSlCertHandler import OpenSSLCertHandler


class ServerHandshake:
    """Handles the TLS handshake process for the server"""

    def __init__(self):
        self.ecdsa_private_key, self.ecdsa_public_key = DigitalSignature.generate_keypair()
        self.private_key = None
        self.public_key = None
        self.signing_private = None
        self.signing_public = None

    def perform_key_exchange(self, client_socket, client_address=None):
        """Perform the complete TLS handshake with a client"""
        try:
            print("Server: Starting TLS 1.3 handshake")
            client_ip = client_address[0] if client_address else ""

            # Initialize cryptographic server materials
            ssl_handler = self._initialize_server_materials()

            # Process ClientHello
            client_data = self._receive_client_hello(client_socket)
            client_public_key_bytes = client_data["public_key_bytes"]
            client_signing_public = client_data["signing_public"]
            client_timestamp = client_data["timestamp"]
            username = client_data["username"]

            # Verify client signature - now including IP
            self._verify_client_signature(
                client_public_key_bytes,
                client_data["signature"],
                client_signing_public,
                client_timestamp,
                username,
                client_ip
            )

            # Prepare and send ServerHello
            client_public_key = KeyExchange.deserialize_public_key(client_public_key_bytes)
            server_data = self._prepare_server_materials(client_timestamp)
            server_public_bytes = server_data["public_bytes"]

            # Create signatures - now including client IP
            signatures = self._create_server_signatures(
                server_public_bytes,
                client_public_key_bytes,
                client_timestamp,
                server_data["signing_private"],
                ssl_handler,
                client_ip
            )

            # Send ServerHello
            self._send_server_hello(
                client_socket,
                ssl_handler,
                server_public_bytes,
                server_data["signing_public_bytes"],
                signatures
            )

            # Derive symmetric key
            symmetric_key = self._derive_symmetric_key(server_data["private_key"], client_public_key)

            return symmetric_key, username

        except Exception as e:
            print(f"Server: Key exchange failed: {str(e)}")
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def _initialize_server_materials(self):
        """Initialize SSL handler and generate key pairs."""
        ssl_handler = OpenSSLCertHandler("E:/swords and sandals/OpenSSL/keys/server.crt",
                                         "E:/swords and sandals/OpenSSL/keys/server.key")
        self.private_key, self.public_key = KeyExchange.generate_key_pair()
        self.signing_private, self.signing_public = DigitalSignature.generate_keypair()
        print("Server: Generated keypairs")
        return ssl_handler

    def _receive_client_hello(self, client_socket):
        """Receive and parse the ClientHello message."""
        # Receive client's public key
        public_key_len = int.from_bytes(client_socket.recv(4), 'big')
        client_public_key_bytes = client_socket.recv(public_key_len)

        # Receive client's signing public key
        signing_key_len = int.from_bytes(client_socket.recv(4), 'big')
        client_signing_public_bytes = client_socket.recv(signing_key_len)

        # Receive timestamp from ClientHello
        client_timestamp = int.from_bytes(client_socket.recv(8), 'big')

        # Receive client's signature
        signature_len = int.from_bytes(client_socket.recv(4), 'big')
        client_signature = client_socket.recv(signature_len)

        # Receive username
        username_len = int.from_bytes(client_socket.recv(4), 'big')
        username = client_socket.recv(username_len).decode('utf-8')

        print("Server: Received ClientHello with key share")

        # Parse client's signing public key
        client_signing_public = DigitalSignature.deserialize_public_key(client_signing_public_bytes)

        return {
            "public_key_bytes": client_public_key_bytes,
            "signing_public": client_signing_public,
            "timestamp": client_timestamp,
            "signature": client_signature,
            "username": username
        }

    def _verify_client_signature(self, client_public_key_bytes, client_signature,
                                 client_signing_public, client_timestamp, username, client_ip=""):
        """Verify the client's signature."""
        # First try with the provided IP
        if DigitalSignature.verify_message(
                client_public_key_bytes.hex(),
                client_signature,
                client_signing_public,
                client_ip,
                client_timestamp,
                username
        ):
            print(f"Server: Verified client signature with IP: {client_ip}")
            return True

        # Next try with localhost/127.0.0.1 if the client IP seems to be a local IP
        if client_ip in ["127.0.0.1", "localhost"] or client_ip.startswith("192.168.") or client_ip.startswith("10."):
            for test_ip in ["127.0.0.1", "localhost", "", "0.0.0.0"]:
                if DigitalSignature.verify_message(
                        client_public_key_bytes.hex(),
                        client_signature,
                        client_signing_public,
                        test_ip,
                        client_timestamp,
                        username
                ):
                    print(f"Server: Verified client signature with alternative local IP: {test_ip}")
                    return True

        # Finally, try with empty IP as a last resort
        if DigitalSignature.verify_message(
                client_public_key_bytes.hex(),
                client_signature,
                client_signing_public,
                "",
                client_timestamp,
                username
        ):
            print("Server: Verified client signature with empty IP")
            return True

        raise ConnectionError("Invalid client signature")

    def _prepare_server_materials(self, client_timestamp):
        """Prepare the server's key material for ServerHello."""
        # Generate server's key share
        server_public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        server_signing_public_bytes = self.signing_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "private_key": self.private_key,
            "public_bytes": server_public_bytes,
            "signing_private": self.signing_private,
            "signing_public_bytes": server_signing_public_bytes,
            "timestamp": client_timestamp
        }

    def _create_server_signatures(self, server_public_bytes, client_public_key_bytes,
                                  timestamp, signing_private, ssl_handler, client_ip=""):
        """Create the signatures for the ServerHello message."""
        # Create server signature with client IP
        server_signature = DigitalSignature.sign_message(
            server_public_bytes.hex(),
            signing_private,
            client_ip,  # Now including client IP
            timestamp,
            "server"
        )

        # Generate OpenSSL signature
        data_to_sign = client_public_key_bytes + server_public_bytes
        openssl_signature = ssl_handler.sign_data(data_to_sign)

        return {
            "server_signature": server_signature,
            "openssl_signature": openssl_signature
        }

    def _send_server_hello(self, client_socket, ssl_handler, server_public_bytes,
                           server_signing_public_bytes, signatures):
        """Send the ServerHello message to the client."""
        # Send certificate
        cert_data = ssl_handler.get_certificate_data()
        client_socket.send(len(cert_data).to_bytes(4, 'big'))
        client_socket.send(cert_data)

        # Send server public key
        client_socket.send(len(server_public_bytes).to_bytes(4, 'big'))
        client_socket.send(server_public_bytes)

        # Send server signing public key
        client_socket.send(len(server_signing_public_bytes).to_bytes(4, 'big'))
        client_socket.send(server_signing_public_bytes)

        # Send server signature
        server_signature = signatures["server_signature"]
        client_socket.send(len(server_signature).to_bytes(4, 'big'))
        client_socket.send(server_signature)

        # Send OpenSSL signature
        openssl_signature = signatures["openssl_signature"]
        client_socket.send(len(openssl_signature).to_bytes(4, 'big'))
        client_socket.send(openssl_signature)

        print("Server: Sent ServerHello with key share")

    def _derive_symmetric_key(self, private_key, client_public_key):
        """Derive the shared symmetric key."""
        shared_secret = KeyExchange.generate_shared_secret(private_key, client_public_key)
        symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
        print("Server: TLS 1.3 handshake completed successfully")
        return symmetric_key