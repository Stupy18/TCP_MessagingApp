from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
import os

from TLS.SecurityConstants import SecurityConstants


class AESGCMCipher:
    """Handles AES-GCM encryption and decryption with fixed block length."""

    @staticmethod
    def split_into_blocks(data):
        """Split data into fixed-length blocks"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        padder = padding.PKCS7(SecurityConstants.BLOCK_SIZE * 8).padder()
        padded_data = padder.update(data) + padder.finalize()

        blocks = []
        for i in range(0, len(padded_data), SecurityConstants.BLOCK_SIZE):
            block = padded_data[i:i + SecurityConstants.BLOCK_SIZE]
            # Pad last block if needed
            if len(block) < SecurityConstants.BLOCK_SIZE:
                block = block.ljust(SecurityConstants.BLOCK_SIZE, b'\0')
            blocks.append(block)

        return blocks

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
    def encrypt(key, plaintext):
        """Encrypts a message using AES-GCM with fixed block length."""
        # Split message into fixed blocks
        blocks = AESGCMCipher.split_into_blocks(plaintext)
        hash_chain = AESGCMCipher.create_hash_chain(blocks)

        # Initialize encryption
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt blocks with their hashes
        encrypted_blocks = []
        for i in range(len(blocks)):
            # Ensure block alignment
            combined = blocks[i] + hash_chain[i]
            # Each combined block is BLOCK_SIZE + HASH_SIZE
            encrypted_block = encryptor.update(combined)
            encrypted_blocks.append(encrypted_block)

        encryptor.finalize()

        # Combine all components with fixed lengths
        result = (
                iv +  # 12 bytes
                encryptor.tag +  # 16 bytes
                len(blocks).to_bytes(4, 'big')  # 4 bytes for block count
        )

        # Add encrypted blocks
        for block in encrypted_blocks:
            result += block

        return result

    @staticmethod
    def decrypt(key, encrypted_message):
        """Decrypts a message and verifies the hash chain."""
        # Extract fixed-length components
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        num_blocks = int.from_bytes(encrypted_message[28:32], 'big')

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Each encrypted block contains data block + hash
        block_with_hash_size = SecurityConstants.BLOCK_SIZE + SecurityConstants.HASH_SIZE
        encrypted_blocks = encrypted_message[32:]

        # Decrypt blocks and separate data from hashes
        decrypted_blocks = []
        verified_hashes = []

        for i in range(num_blocks):
            start = i * block_with_hash_size
            end = start + block_with_hash_size
            encrypted_block = encrypted_blocks[start:end]

            # Decrypt combined block
            decrypted_combined = decryptor.update(encrypted_block)

            # Separate data and hash
            block = decrypted_combined[:SecurityConstants.BLOCK_SIZE]
            block_hash = decrypted_combined[SecurityConstants.BLOCK_SIZE:]

            decrypted_blocks.append(block)
            verified_hashes.append(block_hash)

        # Verify hash chain
        computed_hashes = AESGCMCipher.create_hash_chain(decrypted_blocks)
        if computed_hashes != verified_hashes:
            raise ValueError("Hash chain verification failed!")

        # Remove padding and convert to string
        try:
            unpadder = padding.PKCS7(SecurityConstants.BLOCK_SIZE * 8).unpadder()
            full_message = b''.join(decrypted_blocks)
            unpadded_message = unpadder.update(full_message) + unpadder.finalize()
            return unpadded_message.decode()
        except Exception as e:
            raise ValueError(f"Failed to unpad message: {str(e)}")