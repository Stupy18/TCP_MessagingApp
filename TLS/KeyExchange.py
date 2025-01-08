from cryptography.hazmat.primitives.asymmetric import x25519


class KeyExchange:
    """Handles X25519 key pair generation and shared secret creation."""

    @staticmethod
    def generate_key_pair():
        """Generates a private and public key pair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_shared_secret(private_key, peer_public_key):
        """Generates a shared secret using ECDH."""
        return private_key.exchange(peer_public_key)

    @staticmethod
    def deserialize_public_key(public_key_bytes):
        """
        Deserializes the public key bytes into an X25519 public key object.
        This method is necessary to use the received public key in key exchange.
        """
        return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)