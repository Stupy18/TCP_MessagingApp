import json
import socket
import base64
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
from TLS.AES_GCM_CYPHER import AESGCMCipher, send_encrypted_data, receive_encrypted_data


class ChatClient:
    def __init__(self, message_callback=None):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.connected = False
        self.symmetric_key = None
        self.rooms = []
        self.message_callback = message_callback

    def connect_to_server(self, server_ip, server_port, username):
        try:
            self.client_socket.connect((server_ip, server_port))
            success = self.perform_key_exchange(username)  # Pass username here
            if not success or self.symmetric_key is None:
                raise ConnectionError("Key exchange failed or no symmetric key generated")

            self.username = username
            self.connected = True
            return True, f"Connected to {server_ip}:{server_port}"
        except Exception as e:

            return False, str(e)

    def send_message(self, message):
        try:
            if not self.rooms:
                return False, "Please join a room first"

            formatted_message = f"{self.username}: {message}"


            encrypted_data = self.encrypt_message(formatted_message)


            send_encrypted_data(self.client_socket, encrypted_data)
            return True, formatted_message
        except Exception as e:

            return False, str(e)

    def join_room(self, room_name):
        try:
            if room_name not in self.rooms:

                command = f"/join {room_name}"


                encrypted_data = self.encrypt_message(command)


                send_encrypted_data(self.client_socket, encrypted_data)
                self.rooms.append(room_name)
                return True, room_name

            return False, "Already in room"
        except Exception as e:
            if room_name in self.rooms:
                self.rooms.remove(room_name)

            return False, str(e)

    def leave_room(self, room_name):
        try:
            if room_name in self.rooms:
                self.rooms.remove(room_name)
                encrypted_data = self.encrypt_message(f"/leave {room_name}")
                send_encrypted_data(self.client_socket, encrypted_data)
                return True, room_name
            return False, "Not in room"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        self.connected = False
        try:
            self.client_socket.close()
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            pass
        self.rooms.clear()

    def listen_for_messages(self):
        try:
            while True:
                encrypted_data = receive_encrypted_data(self.client_socket)


                # Decrypt the data directly without base64 decoding
                decrypted_message = AESGCMCipher.decrypt(self.symmetric_key, encrypted_data)


                if self.message_callback:
                    self.message_callback(decrypted_message)
        except Exception as e:

            return False, str(e)

    def perform_key_exchange(self, username):
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

            # Verify server's response
            self._verify_server_signature(server_public_key_bytes, server_signature, server_signing_public, timestamp)
            self._verify_certificate_signature(certificate, public_key_bytes, server_public_key_bytes)

            # Derive keys
            self._derive_symmetric_key(server_public_key_bytes)

            return True

        except Exception as e:
            print(f"Client: Handshake failed: {str(e)}")
            self.symmetric_key = None
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
        return DigitalSignature.sign_message(
            public_key_bytes.hex(),
            self.signing_private,
            "",
            timestamp,
            username
        )

    def _send_client_hello(self, public_key_bytes, signing_public_bytes, timestamp, signature, username):
        """Send the ClientHello message to the server."""
        # Send public key
        self.client_socket.send(len(public_key_bytes).to_bytes(4, 'big'))
        self.client_socket.send(public_key_bytes)

        # Send signing public key
        self.client_socket.send(len(signing_public_bytes).to_bytes(4, 'big'))
        self.client_socket.send(signing_public_bytes)

        # Send timestamp, signature, and username
        self.client_socket.send(timestamp.to_bytes(8, 'big'))
        self.client_socket.send(len(signature).to_bytes(4, 'big'))
        self.client_socket.send(signature)
        username_bytes = username.encode('utf-8')
        self.client_socket.send(len(username_bytes).to_bytes(4, 'big'))
        self.client_socket.send(username_bytes)


    def _receive_server_certificate(self):
        """Receive and parse the server's certificate."""
        cert_len = int.from_bytes(self.client_socket.recv(4), 'big')
        cert_data = self._receive_full_data(cert_len)

        # Parse certificate
        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
        return certificate

    def _receive_full_data(self, data_length):
        """Helper to receive a complete block of data of specified length."""
        data = b''
        remaining = data_length
        while remaining > 0:
            chunk = self.client_socket.recv(min(remaining, 4096))
            if not chunk:
                raise ConnectionError("Connection closed while receiving data")
            data += chunk
            remaining -= len(chunk)
        return data

    def _receive_server_key_material(self):
        """Receive the server's key material."""
        # Receive server public key
        server_key_len = int.from_bytes(self.client_socket.recv(4), 'big')
        server_public_key_bytes = self.client_socket.recv(server_key_len)

        # Receive server signing public key
        server_signing_key_len = int.from_bytes(self.client_socket.recv(4), 'big')
        server_signing_public_bytes = self.client_socket.recv(server_signing_key_len)
        server_signing_public = DigitalSignature.deserialize_public_key(server_signing_public_bytes)

        return server_public_key_bytes, server_signing_public

    def _receive_server_signature(self):
        """Receive the server's signature."""
        server_sig_len = int.from_bytes(self.client_socket.recv(4), 'big')
        server_signature = self.client_socket.recv(server_sig_len)
        return server_signature

    def _verify_server_signature(self, server_public_key_bytes, server_signature, server_signing_public, timestamp):
        """Verify the server's signature."""
        if not DigitalSignature.verify_message(
                server_public_key_bytes.hex(),
                server_signature,
                server_signing_public,
                "",
                timestamp,
                "server"
        ):
            raise ConnectionError("Invalid server signature")

    def _verify_certificate_signature(self, certificate, public_key_bytes, server_public_key_bytes):
        """Verify the certificate signature from the server."""
        openssl_sig_len = int.from_bytes(self.client_socket.recv(4), 'big')
        openssl_signature = self.client_socket.recv(openssl_sig_len)

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
        self.symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)

        if not isinstance(self.symmetric_key, bytes) or len(self.symmetric_key) != 32:
            raise ValueError(f"Invalid symmetric key generated: {len(self.symmetric_key)} bytes")

    def encrypt_message(self, message):
        try:

            if self.symmetric_key is None:
                raise ValueError("No symmetric key available - please ensure you're connected")

            if not isinstance(self.symmetric_key, bytes):
                raise ValueError(f"Invalid symmetric key type: {type(self.symmetric_key)}")

            if len(self.symmetric_key) != 32:
                raise ValueError(f"Invalid symmetric key length: {len(self.symmetric_key)} bytes")


            encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, message)
            # Return the encrypted message directly without base64 encoding
            return encrypted_message
        except Exception as e:

            raise Exception(f"Encryption failed: {str(e)}")