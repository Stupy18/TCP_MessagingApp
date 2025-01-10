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
            success = self.perform_key_exchange()  # Store the result
            if not success or self.symmetric_key is None:
                raise ConnectionError("Key exchange failed or no symmetric key generated")
            print(f"Debug - After connection, symmetric key type: {type(self.symmetric_key)}")
            self.username = username
            self.connected = True
            return True, f"Connected to {server_ip}:{server_port}"
        except Exception as e:
            print(f"Debug - Connection error: {str(e)}")
            return False, str(e)

    def send_message(self, message):
        try:
            if not self.rooms:
                return False, "Please join a room first"

            formatted_message = f"{self.username}: {message}"
            print(f"Debug - Sending message: {formatted_message}")

            encrypted_data = self.encrypt_message(formatted_message)
            print(f"Debug - Encrypted message length: {len(encrypted_data)}")

            send_encrypted_data(self.client_socket, encrypted_data)
            return True, formatted_message
        except Exception as e:
            print(f"Debug - Send message error: {str(e)}")
            return False, str(e)

    def join_room(self, room_name):
        try:
            if room_name not in self.rooms:
                print(f"Debug - Joining room: {room_name}")
                command = f"/join {room_name}"
                print(f"Debug - Sending command: {command}")

                encrypted_data = self.encrypt_message(command)
                print(f"Debug - Encrypted command length: {len(encrypted_data)}")

                send_encrypted_data(self.client_socket, encrypted_data)
                self.rooms.append(room_name)
                return True, room_name

            return False, "Already in room"
        except Exception as e:
            if room_name in self.rooms:
                self.rooms.remove(room_name)
            print(f"Debug - Join room error: {str(e)}")
            return False, str(e)

    def leave_room(self, room_name):
        try:
            if room_name in self.rooms:
                self.rooms.remove(room_name)
                self.client_socket.send(self.encrypt_message(f"/leave {room_name}"))
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
                print(f"Debug - Received encrypted data of length: {len(encrypted_data)}")

                # Decrypt the data directly without base64 decoding
                decrypted_message = AESGCMCipher.decrypt(self.symmetric_key, encrypted_data)
                print(f"Debug - Decrypted message: {decrypted_message}")

                if self.message_callback:
                    self.message_callback(decrypted_message)
        except Exception as e:
            print(f"Debug - Listen error: {str(e)}")
            return False, str(e)

    # ChatClient.py
    # ChatClient.py
    # In ChatClient.py
    def perform_key_exchange(self):
        try:
            print("Client: Starting key exchange")

            # Generate keypairs
            self.private_key, self.public_key = KeyExchange.generate_key_pair()
            self.signing_private, self.signing_public = DigitalSignature.generate_keypair()
            print("Client: Generated keypairs")

            # Prepare keys and signature
            public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            signing_public_bytes = self.signing_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo
            )

            timestamp = int(time.time())  # Store single timestamp for entire exchange
            handshake_data = {
                'ip': self.client_socket.getsockname()[0],
                'timestamp': timestamp,
                'public_key': public_key_bytes.hex()
            }

            signature = DigitalSignature.sign_message(
                public_key_bytes.hex(),
                self.signing_private,
                handshake_data['ip'],
                handshake_data['timestamp'],
                "client"
            )

            print(f"Client Handshake Data: {json.dumps(handshake_data, indent=2)}")

            # Send with length prefixes
            self.client_socket.send(len(public_key_bytes).to_bytes(4, 'big'))
            self.client_socket.send(public_key_bytes)

            self.client_socket.send(len(signing_public_bytes).to_bytes(4, 'big'))
            self.client_socket.send(signing_public_bytes)

            # Also send the timestamp
            self.client_socket.send(timestamp.to_bytes(8, 'big'))

            self.client_socket.send(len(signature).to_bytes(4, 'big'))
            self.client_socket.send(signature)

            print("Client: Sent all keys and signature")

            # Receive server's certificate
            cert_len_bytes = self.client_socket.recv(4)
            if not cert_len_bytes:
                raise ConnectionError("Failed to receive certificate length")
            cert_len = int.from_bytes(cert_len_bytes, 'big')

            cert_data = b''
            remaining = cert_len
            while remaining > 0:
                chunk = self.client_socket.recv(min(remaining, 4096))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving certificate")
                cert_data += chunk
                remaining -= len(chunk)

            try:
                certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
                print("Client: Certificate loaded successfully")
            except Exception as e:
                print(f"Client: Certificate loading failed: {str(e)}")
                raise

            # Receive server's keys and signatures
            server_key_len = int.from_bytes(self.client_socket.recv(4), 'big')
            server_public_key_bytes = self.client_socket.recv(server_key_len)

            # Receive signing public key
            server_signing_key_len = int.from_bytes(self.client_socket.recv(4), 'big')
            server_signing_public_bytes = self.client_socket.recv(server_signing_key_len)
            server_signing_public = DigitalSignature.deserialize_public_key(server_signing_public_bytes)

            server_sig_len = int.from_bytes(self.client_socket.recv(4), 'big')
            server_signature = self.client_socket.recv(server_sig_len)

            server_handshake = {
                'ip': self.client_socket.getpeername()[0],
                'timestamp': timestamp,  # Use same timestamp
                'public_key': server_public_key_bytes.hex()
            }

            if not DigitalSignature.verify_message(
                    server_public_key_bytes.hex(),
                    server_signature,
                    server_signing_public,
                    server_handshake['ip'],
                    server_handshake['timestamp'],
                    "server"
            ):
                raise ConnectionError("Invalid server signature")
            print("Client: Server signature verified")

            # Verify OpenSSL signature
            try:
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
                print("Client: OpenSSL signature verified")
            except Exception as e:
                print(f"Client: OpenSSL verification error: {str(e)}")
                raise ConnectionError("Invalid OpenSSL signature")

            # Complete key exchange
            server_public_key = KeyExchange.deserialize_public_key(server_public_key_bytes)
            shared_secret = KeyExchange.generate_shared_secret(self.private_key, server_public_key)

            # Debug logging
            print(f"Client: Shared secret type: {type(shared_secret)}")
            print(f"Client: Shared secret length: {len(shared_secret)} bytes")

            # Store symmetric key directly
            derived_key = KeyDerivation.derive_symmetric_key(shared_secret)

            # Verify key format
            if not isinstance(derived_key, bytes):
                raise ValueError("Generated symmetric key is not in bytes format")
            if len(derived_key) != 32:
                raise ValueError(f"Invalid symmetric key length: {len(derived_key)} bytes (expected 32)")

            # Store the key
            self.symmetric_key = derived_key

            print(f"Client: Symmetric key type: {type(self.symmetric_key)}")
            print(f"Client: Symmetric key length: {len(self.symmetric_key)} bytes")
            print("Client: Key exchange completed successfully")

            return True

        except Exception as e:
            print(f"Client: Key exchange failed: {str(e)}")
            self.symmetric_key = None  # Reset on failure
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def encrypt_message(self, message):
        try:
            print(f"Debug - encrypt_message called with symmetric key type: {type(self.symmetric_key)}")
            if self.symmetric_key is None:
                raise ValueError("No symmetric key available - please ensure you're connected")

            if not isinstance(self.symmetric_key, bytes):
                raise ValueError(f"Invalid symmetric key type: {type(self.symmetric_key)}")

            if len(self.symmetric_key) != 32:
                raise ValueError(f"Invalid symmetric key length: {len(self.symmetric_key)} bytes")

            print(f"Debug - encrypting message: {message}")
            encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, message)
            # Return the encrypted message directly without base64 encoding
            return encrypted_message
        except Exception as e:
            print(f"Debug - Encryption error: {str(e)}")
            raise Exception(f"Encryption failed: {str(e)}")