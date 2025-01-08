import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyDerivation:
    """Handles symmetric key derivation using HKDF."""

    @staticmethod
    def derive_symmetric_key(shared_secret):
        """
        Derives a symmetric key from a shared secret.
        - key_length: Length of the output key (default: 32 bytes for AES-256).
        - salt_length: Length of the random salt (default: 16 bytes).
        """
        hkdf = HKDF(
            algorithm=SHA256(),
            length=32,  # AES-256 key size
            salt=None,  # Ensure the same salt is used (or no salt)
            info=b'handshake data',  # Ensure the same context string
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)