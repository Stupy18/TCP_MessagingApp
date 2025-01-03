import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519


class KeyExchange:
    """Handles X25519 key pair generation and shared secret creation."""
    BLOCK_SIZE = 16

    @staticmethod
    def pad_block(data):
        """Pad data to fixed block size"""
        padding_length = KeyExchange.BLOCK_SIZE - (len(data) % KeyExchange.BLOCK_SIZE)
        return data + bytes([padding_length] * padding_length)

    @staticmethod
    def generate_key_pair():
        """Generates a private and public key pair with fixed-size output"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Create fixed-size metadata block
        metadata = {
            'algorithm': 'X25519'.ljust(16)[:16].encode(),
            'timestamp': str(int(time.time())).ljust(16)[:16].encode(),
            'version': '1.0'.ljust(16)[:16].encode()
        }

        # Hash each metadata block
        metadata_hash = b''
        for key, value in metadata.items():
            h = hashes.Hash(hashes.SHA256(), backend=default_backend())
            h.update(value)
            metadata_hash += h.finalize()

        return private_key, public_key, metadata_hash

    @staticmethod
    def generate_shared_secret(private_key, peer_public_key, metadata_hash):
        """Generates a shared secret using ECDH with metadata validation"""
        # Generate basic shared secret
        shared_secret = private_key.exchange(peer_public_key)

        # Combine with metadata hash for additional context
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(shared_secret + metadata_hash)
        enhanced_secret = h.finalize()

        # Ensure fixed block size
        return KeyExchange.pad_block(enhanced_secret)


    @staticmethod
    def deserialize_public_key(public_key_bytes):
        """
        Deserializes the public key bytes into an X25519 public key object.
        This method is necessary to use the received public key in key exchange.
        """
        return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
