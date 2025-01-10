from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class KeyDerivation:
    """Handles symmetric key derivation using HKDF."""

    @staticmethod
    def derive_symmetric_key(shared_secret):
        """
        Derives a symmetric key from a shared secret.
        Returns a 32-byte key suitable for AES-256.
        """
        try:
            print(f"Debug - KeyDerivation input type: {type(shared_secret)}")
            # Convert shared_secret to bytes if it isn't already
            if not isinstance(shared_secret, bytes):
                print(f"Debug - Converting shared secret from {type(shared_secret)} to bytes")
                shared_secret = bytes(shared_secret)

            hkdf = HKDF(
                algorithm=SHA256(),
                length=32,  # AES-256 key size
                salt=None,  # No salt for deterministic output
                info=b'handshake data',
                backend=default_backend()
            )

            derived_key = hkdf.derive(shared_secret)
            print(f"Debug - Derived key type: {type(derived_key)}")
            print(f"Debug - Derived key length: {len(derived_key)}")

            if not isinstance(derived_key, bytes):
                print("Debug - Converting derived key to bytes")
                derived_key = bytes(derived_key)

            return derived_key

        except Exception as e:
            print(f"Debug - Key derivation error: {str(e)}")
            raise ValueError(f"Key derivation failed: {str(e)}")