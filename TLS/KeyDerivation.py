import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyDerivation:
    """Handles symmetric key derivation using HKDF."""

    @staticmethod
    def derive_symmetric_key(shared_secret, key_length=32, salt_length=16):
        """
        Derives a symmetric key from a shared secret.
        - key_length: Length of the output key (default: 32 bytes for AES-256).
        - salt_length: Length of the random salt (default: 16 bytes).
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=os.urandom(salt_length),
            info=b'TLS key derivation',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
