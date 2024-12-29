from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature

from TLS.SecurityConstants import SecurityConstants


class DigitalSignature:
    """Handles ECDSA signature generation and verification using fixed block length."""

    @staticmethod
    def generate_keypair():
        """Generate an ECDSA key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def prepare_data_block(data):
        """Prepare a single block of data with fixed length"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            data = str(data).encode('utf-8')

        # Ensure block is exactly BLOCK_SIZE
        if len(data) < SecurityConstants.BLOCK_SIZE:
            # Pad if smaller
            padder = PKCS7(SecurityConstants.BLOCK_SIZE * 8).padder()
            return padder.update(data) + padder.finalize()
        elif len(data) > SecurityConstants.BLOCK_SIZE:
            # Truncate if larger
            return data[:SecurityConstants.BLOCK_SIZE]
        else:
            return data

    @staticmethod
    def create_hash_chain(blocks):
        """Create hash chain zi = h(xi || zi-1)"""
        current_hash = SecurityConstants.INITIAL_HASH
        hash_chain = []

        for block in blocks:
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(block + current_hash)
            current_hash = hasher.finalize()
            hash_chain.append(current_hash)

        return hash_chain

    @staticmethod
    def sign_data(private_key, data_blocks):
        """Sign data using block chain approach"""
        # Ensure all blocks are fixed length
        fixed_blocks = [DigitalSignature.prepare_data_block(block) for block in data_blocks]

        # Create hash chain
        hash_chain = DigitalSignature.create_hash_chain(fixed_blocks)

        # Sign the final hash (last element in hash chain)
        signature = private_key.sign(
            hash_chain[-1],
            ec.ECDSA(hashes.SHA256())
        )

        return signature, fixed_blocks

    @staticmethod
    def verify_signature(public_key, signature, data_blocks):
        """Verify signature using block chain"""
        # Process blocks to fixed length
        fixed_blocks = [DigitalSignature.prepare_data_block(block) for block in data_blocks]

        # Create hash chain
        hash_chain = DigitalSignature.create_hash_chain(fixed_blocks)

        try:
            public_key.verify(
                signature,
                hash_chain[-1],
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def serialize_public_key(public_key):
        """Convert public key to bytes."""
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Ensure fixed length
        return DigitalSignature.prepare_data_block(key_bytes)

    @staticmethod
    def deserialize_public_key(public_key_bytes):
        """Convert bytes back to public key object."""
        return serialization.load_der_public_key(public_key_bytes)