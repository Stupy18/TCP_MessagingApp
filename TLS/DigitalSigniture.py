import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.exceptions import InvalidSignature


class DigitalSignature:
    """Handles ECDSA signature generation and verification using P-256 curve."""

    BLOCK_SIZE = 16

    @staticmethod
    def create_metadata_blocks(client_info):
        """Create fixed-length metadata blocks."""
        metadata = {
            'ip': client_info.get('ip', '').ljust(16)[:16],
            'timestamp': str(int(time.time())).ljust(16)[:16],
            'client_id': client_info.get('id', '').ljust(16)[:16],
            'version': '1.0'.ljust(16)[:16]
        }

        # Concatenate blocks
        metadata_blocks = b''
        for key, value in metadata.items():
            block = value.encode()
            # Hash each block individually
            h = hashes.Hash(hashes.SHA256(), backend=default_backend())
            h.update(block)
            metadata_blocks += h.finalize()

        return metadata_blocks

    @staticmethod
    def generate_keypair():
        """Generate an ECDSA key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign_key_exchange(private_key, client_public_key_bytes, server_public_key_bytes, client_info):
        # Create metadata blocks
        metadata_blocks = DigitalSignature.create_metadata_blocks(client_info)

        # Combine all data
        data_to_sign = metadata_blocks + client_public_key_bytes + server_public_key_bytes

        # Create HMAC of the entire data
        h = hmac.HMAC(private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ), hashes.SHA256(), backend=default_backend())
        h.update(data_to_sign)
        hmac_value = h.finalize()

        # Sign the combined data
        signature = private_key.sign(
            data_to_sign,
            ec.ECDSA(hashes.SHA256())
        )

        return metadata_blocks + hmac_value + signature

    @staticmethod
    def verify_signature(public_key, signature, client_public_key_bytes, server_public_key_bytes):

        data_to_verify = client_public_key_bytes + server_public_key_bytes

        try:
            public_key.verify(
                signature,
                data_to_verify,
                ec.ECDSA(hashes.SHA256())
            )

            return True
        except InvalidSignature:

            return False

    @staticmethod
    def serialize_public_key(public_key):
        """Convert public key to bytes for transmission."""
        return public_key.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_public_key(public_key_bytes):
        """Convert bytes back to public key object."""
        return serialization.load_der_public_key(public_key_bytes)