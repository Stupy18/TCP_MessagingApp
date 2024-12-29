import socket
import base64
import time
import uuid
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from TLS.AES_GCM_CYPHER import AESGCMCipher
from TLS.DigitalSigniture import DigitalSignature
from TLS.KeyDerivation import KeyDerivation
from TLS.KeyExchange import KeyExchange
from TLS.SecurityConstants import SecurityConstants


class ChatClient:
    def __init__(self, message_callback=None):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.connected = False
        self.symmetric_key = None
        self.rooms = []
        self.message_callback = message_callback
        self.device_id = str(uuid.uuid4())

    def connect_to_server(self, server_ip, server_port, username):
        try:
            self.client_socket.connect((server_ip, server_port))
            self.username = username
            # Store client info for key exchange
            self.client_info = {
                'timestamp': str(int(time.time())),
                'ip': server_ip,
                'port': str(server_port),
                'username': username,
                'device_id': self.device_id
            }
            self.perform_key_exchange()
            self.connected = True
            return True, f"Connected to {server_ip}:{server_port}"
        except Exception as e:
            return False, str(e)

    def send_message(self, message):
        try:
            if not self.rooms:
                return False, "Please join a room first"

            formatted_message = f"{self.username}: {message}"
            # Split message into blocks and encrypt
            encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, formatted_message)
            self.client_socket.send(base64.b64encode(encrypted_message))
            return True, formatted_message
        except Exception as e:
            return False, str(e)

    def join_room(self, room_name):
        try:
            if room_name not in self.rooms:
                self.rooms.append(room_name)
                command = f"/join {room_name}"
                # Split command into blocks and encrypt
                encrypted_command = AESGCMCipher.encrypt(self.symmetric_key, command)
                self.client_socket.send(base64.b64encode(encrypted_command))
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
                command = f"/leave {room_name}"
                # Split command into blocks and encrypt
                encrypted_command = AESGCMCipher.encrypt(self.symmetric_key, command)
                self.client_socket.send(base64.b64encode(encrypted_command))
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
            buffer = b''
            while True:
                chunk = self.client_socket.recv(SecurityConstants.BLOCK_SIZE)
                if not chunk:
                    raise ConnectionError("Server connection lost")

                buffer += chunk

                try:
                    # Try to decode complete messages from buffer
                    decoded_data = base64.b64decode(buffer)
                    decrypted_message = AESGCMCipher.decrypt(self.symmetric_key, decoded_data)
                    buffer = b''  # Clear buffer after successful decryption

                    if self.message_callback:
                        self.message_callback(decrypted_message)
                except:
                    # If decoding fails, message might be incomplete
                    continue

        except Exception as e:
            return False, str(e)

    def perform_key_exchange(self):
        try:
            print("\n=== CLIENT KEY EXCHANGE START ===")

            print("1. Generating keypair:")
            # Generate ECDHE keypair
            self.private_key, self.public_key = KeyExchange.generate_key_pair()
            print("   ✓ Generated X25519 keypair")

            # Get public key bytes
            public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            print(f"   ✓ Public key length: {len(public_key_bytes)} bytes")
            print(f"   ✓ Public key preview: {public_key_bytes.hex()[:32]}...")

            print("\n2. Sending client data:")
            # First send the raw 32-byte public key
            self.client_socket.send(public_key_bytes)
            print("   ✓ Sent X25519 public key")

            # Prepare and send client data blocks
            print("   Preparing client blocks:")
            client_blocks = [
                DigitalSignature.prepare_data_block(str(int(time.time()))),
                DigitalSignature.prepare_data_block(self.username),
                DigitalSignature.prepare_data_block(self.device_id)
            ]

            print("   Block structure:")
            for i, block in enumerate(client_blocks):
                print(f"   Block {i + 1}: Length = {len(block)} bytes")
                print(f"   Content preview: {block[:32].hex()}")

            # Send client blocks
            for block in client_blocks:
                self.client_socket.send(block)
            print("   ✓ Sent all client blocks")

            print("\n3. Receiving server certificate:")
            # Receive certificate length
            cert_len_bytes = self.client_socket.recv(4)
            cert_len = int.from_bytes(cert_len_bytes, 'big', signed=False)
            print(f"   Certificate length from bytes: {cert_len_bytes.hex()}")
            print(f"   Expected certificate length: {cert_len}")

            # Receive certificate in chunks
            cert_data = b''
            remaining = cert_len
            while remaining > 0:
                chunk_size = min(SecurityConstants.BLOCK_SIZE, remaining)
                chunk = self.client_socket.recv(chunk_size)
                if not chunk:
                    raise ConnectionError("Connection closed while receiving certificate")
                cert_data += chunk
                remaining -= len(chunk)
                print(f"   Received certificate chunk: {len(chunk)} bytes")

            print(f"   Total certificate received: {len(cert_data)} bytes")

            # Load certificate
            try:
                certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
                print("   ✓ Certificate loaded and verified")
            except Exception as e:
                print(f"   ❌ Certificate loading failed: {str(e)}")
                raise

            print("\n4. Receiving server keys:")
            # Receive server's X25519 public key (exactly 32 bytes)
            server_public_key_bytes = self.client_socket.recv(32)
            if len(server_public_key_bytes) != 32:
                raise ConnectionError(f"Invalid server public key length: {len(server_public_key_bytes)}")
            print(f"   ✓ Received X25519 key, length: {len(server_public_key_bytes)} bytes")
            print(f"   Key preview: {server_public_key_bytes.hex()[:32]}...")

            # Receive server's ECDSA public key
            ecdsa_key_len = int.from_bytes(self.client_socket.recv(4), 'big')
            server_ecdsa_public_key_bytes = self.client_socket.recv(ecdsa_key_len)

            print(f"   ✓ Received ECDSA key, length: {len(server_ecdsa_public_key_bytes)} bytes")

            print("\n5. Receiving server blocks:")
            # Receive server's additional blocks
            server_blocks = []
            for i in range(2):  # timestamp and host
                block = self.client_socket.recv(SecurityConstants.BLOCK_SIZE)
                print(f"   Block {i + 1} received, length: {len(block)} bytes")
                print(f"   Content preview: {block[:32].hex()}")
                server_blocks.append(block)

            print("\n6. Creating verification chain:")
            # Combine all blocks for verification
            all_verify_blocks = [
                                    public_key_bytes
                                ] + client_blocks + [
                                    server_public_key_bytes,
                                    server_ecdsa_public_key_bytes
                                ] + server_blocks

            print(f"   Total blocks in chain: {len(all_verify_blocks)}")
            chain_data = b''.join(all_verify_blocks)
            print(f"   Total chain length: {len(chain_data)} bytes")

            # Calculate chain hash
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(chain_data)
            chain_hash = hasher.finalize()
            print(f"   Chain hash (SHA256): {chain_hash.hex()}")

            print("\n7. Receiving and verifying signatures:")
            # Receive ECDSA signature
            ecdsa_sig_len = int.from_bytes(self.client_socket.recv(4), 'big')
            ecdsa_signature = self.client_socket.recv(ecdsa_sig_len)
            print(f"   ✓ Received ECDSA signature, length: {len(ecdsa_signature)} bytes")
            print(f"   Signature preview: {ecdsa_signature[:32].hex()}")

            # Receive OpenSSL signature
            openssl_sig_len = int.from_bytes(self.client_socket.recv(4), 'big')
            openssl_signature = self.client_socket.recv(openssl_sig_len)
            print(f"   ✓ Received OpenSSL signature, length: {len(openssl_signature)} bytes")
            print(f"   Signature preview: {openssl_signature[:32].hex()}")

            print("\n8. Verifying signatures:")
            # Load server's ECDSA public key
            server_ecdsa_public_key = serialization.load_der_public_key(
                server_ecdsa_public_key_bytes,
                backend=default_backend()
            )

            # Verify ECDSA signature
            server_ecdsa_public_key.verify(
                ecdsa_signature,
                chain_data,
                ec.ECDSA(hashes.SHA256())
            )
            print("   ✓ ECDSA signature verified")

            # Verify OpenSSL signature
            certificate.public_key().verify(
                openssl_signature,
                chain_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("   ✓ OpenSSL signature verified")

            print("\n9. Completing key exchange:")
            # Complete ECDHE key exchange
            server_public_key = KeyExchange.deserialize_public_key(server_public_key_bytes)
            shared_secret = KeyExchange.generate_shared_secret(self.private_key, server_public_key)
            self.symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
            print("   ✓ Generated shared secret")
            print(f"   ✓ Derived symmetric key (length: {len(self.symmetric_key)} bytes)")
            print("   ✓ Key exchange completed successfully")
            print("=== CLIENT KEY EXCHANGE COMPLETE ===\n")

            return True

        except Exception as e:
            print(f"\n❌ CLIENT ERROR: Key exchange failed: {str(e)}")
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def receive_blocks(self, total_size):
        """Helper method to receive data in fixed-size blocks"""
        data = b''
        remaining = total_size
        while remaining > 0:
            block_size = min(remaining, SecurityConstants.BLOCK_SIZE)
            block = self.client_socket.recv(block_size)
            if not block:
                raise ConnectionError("Connection closed while receiving data")
            data += block
            remaining -= len(block)
        return data

    def encrypt_message(self, message):
        try:
            encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, message)
            return base64.b64encode(encrypted_message)
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")