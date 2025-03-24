import json
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend


class DigitalSignature:
    """Handles ECDSA signature generation and verification using P-256 curve with fixed-length blocks."""

    BLOCK_SIZE = 32
    TIMESTAMP_TOLERANCE = 5

    @staticmethod
    def generate_keypair():
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key, private_key.public_key()

    @staticmethod
    def sign_message(message, private_key, ip, timestamp, username):
        app_data = {
            'timestamp': timestamp,
            'username': username,
            'message': message
        }

        serialized_data = json.dumps(app_data).encode()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        z_prev = b''

        for i in range(0, len(serialized_data), DigitalSignature.BLOCK_SIZE):
            block = serialized_data[i:i + DigitalSignature.BLOCK_SIZE]
            if len(block) < DigitalSignature.BLOCK_SIZE:
                block += b'\0' * (DigitalSignature.BLOCK_SIZE - len(block))
            digest.update(block + z_prev)
            z_prev = digest.finalize()
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

        return private_key.sign(z_prev, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def verify_message(message, signature, public_key, ip, timestamp, username):
        # Add timestamp verification with tolerance
        current_time = int(time.time())
        time_diff = abs(current_time - timestamp)
        if time_diff > DigitalSignature.TIMESTAMP_TOLERANCE:
            return False

        app_data = {
            'timestamp': timestamp,
            'username': username,
            'message': message
        }

        try:
            serialized_data = json.dumps(app_data).encode()

            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            z_prev = b''

            for i in range(0, len(serialized_data), DigitalSignature.BLOCK_SIZE):
                block = serialized_data[i:i + DigitalSignature.BLOCK_SIZE]
                if len(block) < DigitalSignature.BLOCK_SIZE:
                    block += b'\0' * (DigitalSignature.BLOCK_SIZE - len(block))
                digest.update(block + z_prev)
                z_prev = digest.finalize()
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

            try:
                public_key.verify(signature, z_prev, ec.ECDSA(hashes.SHA256()))
                return True
            except InvalidSignature:
                print("Invalid signature detected")
                return False
        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False

    @staticmethod
    def sign_key_exchange(private_key, client_public_key_bytes, server_public_key_bytes):
        data_to_sign = client_public_key_bytes + server_public_key_bytes
        return private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def verify_signature(public_key, signature, client_public_key_bytes, server_public_key_bytes):
        data_to_verify = client_public_key_bytes + server_public_key_bytes
        try:
            public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)

    @staticmethod
    def deserialize_public_key(public_key_bytes):
        return serialization.load_der_public_key(public_key_bytes)