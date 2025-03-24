# RSAKeyExchange.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os


class RSAKeyExchange:
    """Handles RSA key pair generation and encryption for TLS 1.2 style key exchange."""

    @staticmethod
    def generate_key_pair(key_size=4096):
        """Generates an RSA private and public key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def encrypt_pre_master_secret(public_key, pre_master_secret=None):
        """
        Encrypts a pre-master secret using the server's public key.
        If no pre_master_secret is provided, a random one is generated.
        """
        # Generate random pre-master secret if not provided
        if pre_master_secret is None:
            pre_master_secret = os.urandom(48)  # TLS 1.2 uses a 48-byte pre-master secret

        encrypted_secret = public_key.encrypt(
            pre_master_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_secret, pre_master_secret

    @staticmethod
    def decrypt_pre_master_secret(private_key, encrypted_pre_master_secret):
        """Decrypts the pre-master secret using the server's private key."""
        pre_master_secret = private_key.decrypt(
            encrypted_pre_master_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return pre_master_secret

    @staticmethod
    def serialize_public_key(public_key):
        """Serializes the public key for transmission."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_public_key(public_key_bytes):
        """Deserializes the public key bytes into an RSA public key object."""
        try:
            if not isinstance(public_key_bytes, bytes):
                raise ValueError("Public key bytes must be bytes")
            return serialization.load_der_public_key(
                public_key_bytes,
                backend=default_backend()
            )
        except Exception as e:
            raise ValueError(f"Failed to deserialize public key: {str(e)}")