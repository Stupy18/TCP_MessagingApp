import socket
import base64
import time
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from TLS.DigitalSigniture import DigitalSignature
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.AES_GCM_CYPHER import AESGCMCipher

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
            self.perform_key_exchange()
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
            self.client_socket.send(self.encrypt_message(formatted_message))
            return True, formatted_message
        except Exception as e:
            return False, str(e)

    def join_room(self, room_name):
        try:
            if room_name not in self.rooms:
                self.rooms.append(room_name)
                self.client_socket.send(self.encrypt_message(f"/join {room_name}"))
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
                encrypted_data = self.client_socket.recv(1024)
                if not encrypted_data:
                    raise ConnectionError("Server connection lost")

                decoded_data = base64.b64decode(encrypted_data)

                # Process in fixed blocks
                block_size = AESGCMCipher.BLOCK_SIZE + 60  # Include IV + HMAC + Tag
                blocks = [decoded_data[i:i + block_size]
                          for i in range(0, len(decoded_data), block_size)]

                decrypted_blocks = []
                for block in blocks:
                    if len(block) == block_size:  # Only process complete blocks
                        decrypted_block = AESGCMCipher.decrypt(
                            self.symmetric_key,
                            block,
                            auth_key=self.auth_key
                        )
                        decrypted_blocks.append(decrypted_block)

                message = b''.join(decrypted_blocks)
                if self.message_callback:
                    self.message_callback(message.decode().strip())
        except Exception as e:
            return False, str(e)

    def perform_key_exchange(self):  # Client side
        try:
            print("Client: Starting key exchange")

            # Generate keypair with metadata - Fixed the unpack issue
            self.private_key, self.public_key, self.metadata_hash = KeyExchange.generate_key_pair()
            print("Client: Generated ECDHE keypair")

            # Get public key bytes
            self.public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            print(f"Client: Public key length: {len(self.public_key_bytes)}")

            # Create client info for digital signature
            client_info = {
                'ip': self.client_socket.getsockname()[0],
                'id': str(uuid.uuid4()),
                'timestamp': str(int(time.time()))
            }

            # Send client's public key
            self.client_socket.send(self.public_key_bytes)
            print("Client: Sent public key")

            # Receive server's certificate length and data
            cert_len_bytes = self.client_socket.recv(4)
            if not cert_len_bytes:
                raise ConnectionError("Failed to receive certificate length")
            cert_len = int.from_bytes(cert_len_bytes, 'big')
            print(f"Client: Expected certificate length: {cert_len}")

            # Receive certificate in chunks if necessary
            cert_data = b''
            remaining = cert_len
            while remaining > 0:
                chunk = self.client_socket.recv(min(remaining, 4096))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving certificate")
                cert_data += chunk
                remaining -= len(chunk)
            print(f"Client: Received certificate, length: {len(cert_data)}")

            # Verify certificate
            try:
                certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
                print("Client: Certificate loaded successfully")
            except Exception as e:
                print(f"Client: Certificate loading failed: {str(e)}")
                raise

            # Receive server's public keys and signatures with length checks
            server_public_key_bytes = self.client_socket.recv(32)  # X25519 key is always 32 bytes
            print(f"Client: Received server public key, length: {len(server_public_key_bytes)}")

            ecdsa_key_len = int.from_bytes(self.client_socket.recv(4), 'big')
            server_ecdsa_public_key_bytes = self.client_socket.recv(ecdsa_key_len)
            print(f"Client: Received ECDSA public key, length: {len(server_ecdsa_public_key_bytes)}")

            ecdsa_sig_len = int.from_bytes(self.client_socket.recv(4), 'big')
            ecdsa_signature = self.client_socket.recv(ecdsa_sig_len)
            print(f"Client: Received ECDSA signature, length: {len(ecdsa_signature)}")

            openssl_sig_len = int.from_bytes(self.client_socket.recv(4), 'big')
            openssl_signature = self.client_socket.recv(openssl_sig_len)
            print(f"Client: Received OpenSSL signature, length: {len(openssl_signature)}")

            # Verify signatures
            server_public_key = KeyExchange.deserialize_public_key(server_public_key_bytes)
            server_ecdsa_public_key = DigitalSignature.deserialize_public_key(server_ecdsa_public_key_bytes)

            # Verify ECDSA signature
            if not DigitalSignature.verify_signature(
                    server_ecdsa_public_key,
                    ecdsa_signature,
                    self.public_key_bytes,
                    server_public_key_bytes
            ):
                print("Client: ECDSA signature verification failed")
                raise ConnectionError("Invalid ECDSA signature")
            print("Client: ECDSA signature verified")

            data_to_verify = self.public_key_bytes + server_public_key_bytes
            print(f"Client: Data to verify length: {len(data_to_verify)}")
            print(f"Client: First few bytes to verify: {data_to_verify[:32].hex()}")

            # Verify OpenSSL signature
            try:
                certificate.public_key().verify(
                    openssl_signature,
                    data_to_verify,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Client: OpenSSL signature verified successfully")
            except Exception as e:
                print(f"Client: OpenSSL verification error: {str(e)}")
                raise ConnectionError("Invalid OpenSSL signature")

            # Create fixed-block signature with metadata
            signature = DigitalSignature.sign_key_exchange(
                self.private_key,
                self.public_key_bytes,
                server_public_key_bytes,
                client_info
            )

            # Complete key exchange with enhanced security including metadata
            shared_secret = KeyExchange.generate_shared_secret(
                self.private_key,
                server_public_key,
                self.metadata_hash  # Using stored metadata_hash
            )

            # Derive keys with enhanced context
            key_material = KeyDerivation.derive_symmetric_key(
                shared_secret,
                context_info=f"{client_info['ip']}:{client_info['id']}".encode()
            )

            # Store both keys from the derived material
            self.symmetric_key = key_material['encryption_key']
            self.auth_key = key_material['auth_key']

            print("Client: Key exchange completed successfully")
            return True

        except Exception as e:
            print(f"Client: Key exchange failed: {str(e)}")
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def encrypt_message(self, message):
        try:
            # Convert message to blocks and pad
            if isinstance(message, str):
                message = message.encode()

            padded_data = AESGCMCipher.pad_data(message)

            # Process in fixed blocks
            blocks = [padded_data[i:i + AESGCMCipher.BLOCK_SIZE]
                      for i in range(0, len(padded_data), AESGCMCipher.BLOCK_SIZE)]

            # Encrypt each block
            encrypted_blocks = []
            for block in blocks:
                encrypted_block = AESGCMCipher.encrypt(
                    self.symmetric_key,
                    block,
                    auth_key=self.auth_key
                )
                encrypted_blocks.append(encrypted_block)

            return base64.b64encode(b''.join(encrypted_blocks))
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")