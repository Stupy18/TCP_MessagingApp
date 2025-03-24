from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class KeyDerivation:
    """Handles symmetric key derivation using HKDF."""

    @staticmethod
    def derive_symmetric_key(pre_master_secret):
        """
        Derives a symmetric key from a pre-master secret using TLS 1.2 style PRF.
        Returns a 32-byte key suitable for AES-256.
        """
        try:
            # Convert pre_master_secret to bytes if it isn't already
            if not isinstance(pre_master_secret, bytes):
                pre_master_secret = bytes(pre_master_secret)

            hkdf = HKDF(
                algorithm=SHA256(),
                length=32,  # AES-256 key size
                salt=None,  # No salt for deterministic output
                info=b'tls12 handshake data',
                backend=default_backend()
            )

            derived_key = hkdf.derive(pre_master_secret)

            if not isinstance(derived_key, bytes):
                derived_key = bytes(derived_key)

            return derived_key

        except Exception as e:
            raise ValueError(f"Key derivation failed: {str(e)}")