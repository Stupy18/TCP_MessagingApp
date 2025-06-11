import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import PublicFormat
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from TLS.DigitalSigniture import DigitalSignature
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation


class ClientHandshake:
    """Handles the TLS handshake process for the client"""

    def __init__(self, connection_manager):
        self.connection_manager = connection_manager
        self.private_key = None
        self.public_key = None
        self.signing_private = None
        self.signing_public = None

    def perform_key_exchange(self, username):
        """Perform the complete TLS handshake with the server"""
        try:
            # Generate keys and prepare ClientHello
            self._generate_key_pairs()
            public_key_bytes, signing_public_bytes = self._prepare_key_bytes()
            timestamp = int(time.time())

            # Sign and send ClientHello
            signature = self._create_client_hello_signature(public_key_bytes, timestamp, username)
            self._send_client_hello(public_key_bytes, signing_public_bytes, timestamp, signature, username)

            # Receive and process ServerHello
            certificate = self._receive_server_certificate()
            server_public_key_bytes, server_signing_public = self._receive_server_key_material()
            server_signature = self._receive_server_signature()

            # Get server IP from the socket
            server_ip = self.connection_manager.get_server_address()[0]

            # Verify server's response
            self._verify_server_signature(
                server_public_key_bytes,
                server_signature,
                server_signing_public,
                timestamp,
                server_ip
            )
            self._verify_certificate_signature(certificate, public_key_bytes, server_public_key_bytes)

            # Derive and set symmetric key
            symmetric_key = self._derive_symmetric_key(server_public_key_bytes)
            self.connection_manager.set_symmetric_key(symmetric_key)

            return True

        except Exception as e:
            print(f"Client: Handshake failed: {str(e)}")
            raise ConnectionError(f"Handshake failed: {str(e)}")

    def _generate_key_pairs(self):
        """Generate X25519 and ECDSA key pairs for the handshake."""
        self.private_key, self.public_key = KeyExchange.generate_key_pair()
        self.signing_private, self.signing_public = DigitalSignature.generate_keypair()

    def _prepare_key_bytes(self):
        """Prepare the serialized key bytes for transmission."""
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        signing_public_bytes = self.signing_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_bytes, signing_public_bytes

    def _create_client_hello_signature(self, public_key_bytes, timestamp, username):
        """Create the signature for the ClientHello message."""
        # Get server IP from the socket
        server_ip = self.connection_manager.get_server_address()[0]

        return DigitalSignature.sign_message(
            public_key_bytes.hex(),
            self.signing_private,
            server_ip,  # Include server IP
            timestamp,
            username
        )

    def _send_client_hello(self, public_key_bytes, signing_public_bytes, timestamp, signature, username):
        """Send the ClientHello message to the server."""
        client_socket = self.connection_manager.client_socket

        # Send public key
        client_socket.send(len(public_key_bytes).to_bytes(4, 'big'))
        client_socket.send(public_key_bytes)

        # Send signing public key
        client_socket.send(len(signing_public_bytes).to_bytes(4, 'big'))
        client_socket.send(signing_public_bytes)

        # Send timestamp, signature, and username
        client_socket.send(timestamp.to_bytes(8, 'big'))
        client_socket.send(len(signature).to_bytes(4, 'big'))
        client_socket.send(signature)
        username_bytes = username.encode('utf-8')
        client_socket.send(len(username_bytes).to_bytes(4, 'big'))
        client_socket.send(username_bytes)

    def _receive_server_certificate(self):
        """Receive and parse the server's certificate."""
        client_socket = self.connection_manager.client_socket
        cert_len = int.from_bytes(client_socket.recv(4), 'big')
        cert_data = self._receive_full_data(cert_len)

        # Parse certificate
        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
        return certificate

    def _receive_full_data(self, data_length):
        """Helper to receive a complete block of data of specified length."""
        client_socket = self.connection_manager.client_socket
        data = b''
        remaining = data_length
        while remaining > 0:
            chunk = client_socket.recv(min(remaining, 4096))
            if not chunk:
                raise ConnectionError("Connection closed while receiving data")
            data += chunk
            remaining -= len(chunk)
        return data

    def _receive_server_key_material(self):
        """Receive the server's key material."""
        client_socket = self.connection_manager.client_socket

        # Receive server public key
        server_key_len = int.from_bytes(client_socket.recv(4), 'big')
        server_public_key_bytes = client_socket.recv(server_key_len)

        # Receive server signing public key
        server_signing_key_len = int.from_bytes(client_socket.recv(4), 'big')
        server_signing_public_bytes = client_socket.recv(server_signing_key_len)
        server_signing_public = DigitalSignature.deserialize_public_key(server_signing_public_bytes)

        return server_public_key_bytes, server_signing_public

    def _receive_server_signature(self):
        """Receive the server's signature."""
        client_socket = self.connection_manager.client_socket
        server_sig_len = int.from_bytes(client_socket.recv(4), 'big')
        server_signature = client_socket.recv(server_sig_len)
        return server_signature

    def _verify_server_signature(self, server_public_key_bytes, server_signature,
                                 server_signing_public, timestamp, server_ip=""):
        """Verify the server's signature."""
        # First try with the provided server IP
        if DigitalSignature.verify_message(
                server_public_key_bytes.hex(),
                server_signature,
                server_signing_public,
                server_ip,
                timestamp,
                "server"
        ):
            return True

        # If connecting to a local server, try common local IPs
        if server_ip in ["127.0.0.1", "localhost"] or server_ip.startswith("192.168.") or server_ip.startswith("10."):
            for test_ip in ["127.0.0.1", "localhost", "", "0.0.0.0"]:
                if DigitalSignature.verify_message(
                        server_public_key_bytes.hex(),
                        server_signature,
                        server_signing_public,
                        test_ip,
                        timestamp,
                        "server"
                ):
                    print(f"Client: Verified server signature with alternative local IP: {test_ip}")
                    return True

        # Finally try with empty IP as fallback
        if DigitalSignature.verify_message(
                server_public_key_bytes.hex(),
                server_signature,
                server_signing_public,
                "",
                timestamp,
                "server"
        ):
            print("Client: Verified server signature with empty IP fallback")
            return True

        raise ConnectionError("Invalid server signature")

    def _verify_certificate_signature(self, certificate, public_key_bytes, server_public_key_bytes):
        """Verify the certificate signature from the server."""
        client_socket = self.connection_manager.client_socket
        openssl_sig_len = int.from_bytes(client_socket.recv(4), 'big')
        openssl_signature = client_socket.recv(openssl_sig_len)

        data_to_verify = public_key_bytes + server_public_key_bytes
        certificate.public_key().verify(
            openssl_signature,
            data_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def _derive_symmetric_key(self, server_public_key_bytes):
        """Derive the shared symmetric key."""
        # Generate shared secret
        server_public_key = KeyExchange.deserialize_public_key(server_public_key_bytes)
        shared_secret = KeyExchange.generate_shared_secret(self.private_key, server_public_key)

        # Derive final symmetric key
        symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)

        if not isinstance(symmetric_key, bytes) or len(symmetric_key) != 32:
            raise ValueError(f"Invalid symmetric key generated: {len(symmetric_key)} bytes")

        return symmetric_key