# secure_protocol.py
from typing import Tuple, Dict
import base64
from KeyExchange import KeyExchange
from KeyDerivation import KeyDerivation
from AES_GCM_CYPHER import AESGCMCipher


class SecureProtocol:
    """Handles the secure communication protocol for both client and server."""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_secrets = {}  # Maps socket/client to their shared secret
        self.symmetric_keys = {}  # Maps socket/client to their symmetric key
        self._initialize_keypair()

    def _initialize_keypair(self):
        """Initialize the X25519 key pair."""
        self.private_key, self.public_key = KeyExchange.generate_key_pair()

    def get_public_key_bytes(self) -> bytes:
        """Get the public key in bytes format for transmission."""
        return self.public_key.public_bytes()

    def handle_key_exchange(self, socket, peer_public_key_b64: str) -> None:
        """
        Handle the key exchange process with a peer.

        Args:
            socket: The socket connection with the peer
            peer_public_key_b64: Base64 encoded peer's public key
        """
        # Decode the peer's public key
        peer_public_key_bytes = base64.b64decode(peer_public_key_b64)
        peer_public_key = KeyExchange.deserialize_public_key(peer_public_key_bytes)

        # Generate shared secret
        shared_secret = KeyExchange.generate_shared_secret(self.private_key, peer_public_key)
        self.shared_secrets[socket] = shared_secret

        # Derive symmetric key
        symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
        self.symmetric_keys[socket] = symmetric_key

    def encrypt_message(self, socket, message: str) -> str:
        """
        Encrypt a message for a specific peer.

        Args:
            socket: The socket connection with the peer
            message: The plaintext message

        Returns:
            Base64 encoded encrypted message
        """
        key = self.symmetric_keys.get(socket)
        if not key:
            raise ValueError("No symmetric key available for this peer")

        encrypted = AESGCMCipher.encrypt(key, message)
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_message(self, socket, encrypted_message_b64: str) -> str:
        """
        Decrypt a message from a specific peer.

        Args:
            socket: The socket connection with the peer
            encrypted_message_b64: Base64 encoded encrypted message

        Returns:
            Decrypted message
        """
        key = self.symmetric_keys.get(socket)
        if not key:
            raise ValueError("No symmetric key available for this peer")

        encrypted = base64.b64decode(encrypted_message_b64)
        return AESGCMCipher.decrypt(key, encrypted)

    def remove_peer(self, socket):
        """Clean up keys when a peer disconnects."""
        self.shared_secrets.pop(socket, None)
        self.symmetric_keys.pop(socket, None)