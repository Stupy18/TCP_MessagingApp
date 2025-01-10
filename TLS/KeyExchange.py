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
        try:
            # Ensure we're getting a valid shared secret
            shared_secret = private_key.exchange(peer_public_key)
            if not isinstance(shared_secret, bytes):
                raise ValueError("Shared secret must be bytes")
            return shared_secret
        except Exception as e:
            raise ValueError(f"Failed to generate shared secret: {str(e)}")

    @staticmethod
    def deserialize_public_key(public_key_bytes):
        """
        Deserializes the public key bytes into an X25519 public key object.
        """
        try:
            if not isinstance(public_key_bytes, bytes):
                raise ValueError("Public key bytes must be bytes")
            return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        except Exception as e:
            raise ValueError(f"Failed to deserialize public key: {str(e)}")