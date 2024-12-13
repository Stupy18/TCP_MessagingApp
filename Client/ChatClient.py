import socket
import base64
from cryptography.hazmat.primitives import serialization

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
                decrypted_message = AESGCMCipher.decrypt(self.symmetric_key, decoded_data)
                if self.message_callback:
                    self.message_callback(decrypted_message)
        except Exception as e:
            return False, str(e)

    def perform_key_exchange(self):
        try:
            print("\n=== Client Key Exchange Start ===")

            # Generate ECDHE keypair
            self.private_key, self.public_key = KeyExchange.generate_key_pair()
            print("✓ Generated ECDHE keypair")

            # Get ECDHE public key bytes
            public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            print(f"✓ Client ECDHE public key (first 16 bytes): {public_key_bytes[:16].hex()}")

            # Send client's public key
            self.client_socket.send(public_key_bytes)
            print("✓ Sent ECDHE public key to server")

            # Receive server's ECDHE public key and ECDSA signature
            server_public_key_bytes = self.client_socket.recv(32)
            if not server_public_key_bytes:
                raise ConnectionError("Failed to receive server's public key")
            print(f"✓ Received server ECDHE public key (first 16 bytes): {server_public_key_bytes[:16].hex()}")

            # Receive server's ECDSA public key
            server_ecdsa_public_key_bytes = self.client_socket.recv(512)
            if not server_ecdsa_public_key_bytes:
                raise ConnectionError("Failed to receive server's ECDSA public key")
            print("✓ Received server ECDSA public key")

            # Receive signature
            signature = self.client_socket.recv(128)
            if not signature:
                raise ConnectionError("Failed to receive server's signature")
            print(f"✓ Received server signature (first 16 bytes): {signature[:16].hex()}")

            # Deserialize server's keys
            server_public_key = KeyExchange.deserialize_public_key(server_public_key_bytes)
            server_ecdsa_public_key = DigitalSignature.deserialize_public_key(server_ecdsa_public_key_bytes)
            print("✓ Deserialized server keys")

            # Verify server's signature
            if not DigitalSignature.verify_signature(
                    server_ecdsa_public_key,
                    signature,
                    public_key_bytes,
                    server_public_key_bytes
            ):
                print("❌ SIGNATURE VERIFICATION FAILED!")
                raise ConnectionError("Invalid server signature")
            print("✓ Verified server signature successfully!")

            # Complete ECDHE key exchange
            shared_secret = KeyExchange.generate_shared_secret(self.private_key, server_public_key)
            print(f"✓ Generated shared secret (first 16 bytes): {shared_secret[:16].hex()}")

            self.symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
            print(f"✓ Derived symmetric key (first 16 bytes): {self.symmetric_key[:16].hex()}")

            print("=== Client Key Exchange Complete ===\n")
            return True

        except Exception as e:
            print(f"❌ Key exchange failed: {str(e)}")
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def encrypt_message(self, message):
        try:
            encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, message)
            return base64.b64encode(encrypted_message)
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")