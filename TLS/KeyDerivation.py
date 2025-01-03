import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyDerivation:
    """Handles symmetric key derivation using HKDF."""
    BLOCK_SIZE = 32  # Fixed block size for derived keys

    @staticmethod
    def derive_symmetric_key(shared_secret, context_info=None):
        """
        Derives symmetric keys using HKDF with fixed block sizes and additional context.
        Returns both encryption key and authentication key.
        """
        if context_info is None:
            context_info = b'default_context'

        # Pad context info to fixed block size
        padded_context = context_info + b'\x00' * (KeyDerivation.BLOCK_SIZE - len(context_info))

        # Create HKDF instance
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KeyDerivation.BLOCK_SIZE * 2,  # Generate two keys
            salt=os.urandom(KeyDerivation.BLOCK_SIZE),
            info=padded_context,
            backend=default_backend()
        )

        # Derive key material
        key_material = hkdf.derive(shared_secret)

        # Split into encryption and authentication keys
        encryption_key = key_material[:KeyDerivation.BLOCK_SIZE]
        auth_key = key_material[KeyDerivation.BLOCK_SIZE:]

        # Create HMAC of the keys for verification
        h = hmac.HMAC(auth_key, hashes.SHA256(), backend=default_backend())
        h.update(encryption_key)
        key_verification = h.finalize()

        return {
            'encryption_key': encryption_key,
            'auth_key': auth_key,
            'verification': key_verification
        }
