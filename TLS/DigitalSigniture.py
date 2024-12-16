from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.exceptions import InvalidSignature


class DigitalSignature:
    """Handles ECDSA signature generation and verification using P-256 curve."""

    @staticmethod
    def generate_keypair():
        """Generate an ECDSA key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign_key_exchange(private_key, client_public_key_bytes, server_public_key_bytes):

        data_to_sign = client_public_key_bytes + server_public_key_bytes

        signature = private_key.sign(
            data_to_sign,
            ec.ECDSA(hashes.SHA256())
        )

        return signature

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