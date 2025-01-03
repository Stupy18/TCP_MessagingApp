from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
import os
import time

from TLS.SecurityConstants import SecurityConstants


class AESGCMCipher:
    """Handles AES-GCM encryption and decryption with fixed block length."""

    @staticmethod
    def secure_pad_block(data, block_size):
        """
        Securely pad data to block size using random bytes except for the last byte
        which indicates padding length (similar to PKCS7 but with random padding bytes)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        padding_length = block_size - (len(data) % block_size)
        if padding_length == 0:
            padding_length = block_size

        # Generate random padding bytes
        random_padding = os.urandom(padding_length - 1)
        # Last byte is padding length (PKCS7 style)
        padding = random_padding + bytes([padding_length])

        return data + padding

    @staticmethod
    def secure_unpad_block(padded_data):
        """Remove secure random padding"""
        if not padded_data:
            raise ValueError("Empty data")

        padding_length = padded_data[-1]
        if padding_length == 0 or padding_length > len(padded_data):
            raise ValueError("Invalid padding")

        return padded_data[:-padding_length]

    @staticmethod
    def split_into_blocks(data):
        """Split data into fixed-length blocks with random padding"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # First apply secure random padding
        padded_data = AESGCMCipher.secure_pad_block(data, SecurityConstants.BLOCK_SIZE)

        blocks = []
        for i in range(0, len(padded_data), SecurityConstants.BLOCK_SIZE):
            block = padded_data[i:i + SecurityConstants.BLOCK_SIZE]
            if len(block) < SecurityConstants.BLOCK_SIZE:
                # This should never happen due to padding, but just in case
                raise ValueError("Block size error")
            blocks.append(block)

            print(f"\nMessage Block {i // SecurityConstants.BLOCK_SIZE + 1}:")
            print(f"Original length: {len(block)} bytes")
            print(f"Padded block hex: {block.hex()}")
            # Try to show readable parts
            readable = block.decode('utf-8', errors='replace')
            print(f"Readable content: {readable}")
            print("-" * 50)

        return blocks

    @staticmethod
    def encrypt(key, plaintext):
        """Encrypts a message using AES-GCM with fixed block length and hash chain."""
        print("\n=== ENCRYPTING MESSAGE ===")
        print(f"Original message: {plaintext}")
        print(f"Original length: {len(plaintext.encode('utf-8'))} bytes")

        # Generate message ID (timestamp + nonce)
        timestamp = int(time.time()).to_bytes(8, 'big')
        nonce = os.urandom(4)
        message_id = timestamp + nonce

        # Split into blocks with random padding
        blocks = AESGCMCipher.split_into_blocks(plaintext)
        print(f"\nSplit into {len(blocks)} fixed-size blocks")

        # Create and store hash chain
        hash_chain = []
        current_hash = SecurityConstants.INITIAL_HASH
        for i, block in enumerate(blocks):
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(message_id + block + current_hash)
            current_hash = hasher.finalize()
            hash_chain.append(current_hash)
            print(f"\nBlock {i + 1} hash chain:")
            print(f"Hash: {current_hash.hex()}")

        # Initialize encryption
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Include message_id in authenticated data
        encryptor.authenticate_additional_data(message_id)

        # Encrypt blocks with their hashes
        encrypted_blocks = []
        for i, (block, block_hash) in enumerate(zip(blocks, hash_chain)):
            # Combine block, its hash, and message ID
            combined = message_id + block + block_hash
            encrypted_block = encryptor.update(combined)
            encrypted_blocks.append(encrypted_block)

            print(f"\nEncrypted Block {i + 1}:")
            print(f"Length: {len(encrypted_block)} bytes")
            print(f"Encrypted hex: {encrypted_block.hex()}")

        encryptor.finalize()

        # Format: iv + tag + message_id + num_blocks + encrypted_blocks
        result = (
                iv +  # 12 bytes
                encryptor.tag +  # 16 bytes
                message_id +  # 12 bytes
                len(blocks).to_bytes(4, 'big')  # 4 bytes
        )

        # Add encrypted blocks
        for block in encrypted_blocks:
            result += block

        print("\nFinal encrypted message:")
        print(f"Total length: {len(result)} bytes")
        print(f"Message ID: {message_id.hex()}")
        print(f"Final hex: {result.hex()}")
        print("=== ENCRYPTION COMPLETE ===\n")

        return result

    @staticmethod
    def decrypt(key, encrypted_message):
        """Decrypts a message and verifies the hash chain."""
        print("\n=== DECRYPTING MESSAGE ===")

        try:
            # Extract message components
            if len(encrypted_message) < 44:  # Minimum length check (12+16+12+4 bytes)
                raise ValueError("Message too short")

            iv = encrypted_message[:12]
            tag = encrypted_message[12:28]
            message_id = encrypted_message[28:40]
            num_blocks = int.from_bytes(encrypted_message[40:44], 'big')

            print(f"Message ID: {message_id.hex()}")
            print(f"IV: {iv.hex()}")
            print(f"Tag: {tag.hex()}")
            print(f"Number of blocks: {num_blocks}")

            # Setup cipher for decryption
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            # Authenticate message ID
            decryptor.authenticate_additional_data(message_id)

            # Calculate block sizes
            block_size = SecurityConstants.BLOCK_SIZE + SecurityConstants.HASH_SIZE + 12
            expected_size = 44 + (block_size * num_blocks)  # Header + blocks

            if len(encrypted_message) != expected_size:
                raise ValueError(f"Invalid message size. Expected {expected_size}, got {len(encrypted_message)}")

            encrypted_blocks = encrypted_message[44:]
            decrypted_blocks = []
            current_hash = SecurityConstants.INITIAL_HASH

            # Process each block once
            for i in range(num_blocks):
                start = i * block_size
                end = start + block_size
                encrypted_block = encrypted_blocks[start:end]

                # Decrypt block
                decrypted_combined = decryptor.update(encrypted_block)

                # Split into components
                block_message_id = decrypted_combined[:12]
                block = decrypted_combined[12:12 + SecurityConstants.BLOCK_SIZE]
                block_hash = decrypted_combined[12 + SecurityConstants.BLOCK_SIZE:]

                # Verify message ID and hash chain
                if block_message_id != message_id:
                    raise ValueError("Message ID mismatch - potential replay attack")

                hasher = hashes.Hash(hashes.SHA256())
                hasher.update(message_id + block + current_hash)
                computed_hash = hasher.finalize()

                if computed_hash != block_hash:
                    raise ValueError(f"Hash chain verification failed for block {i + 1}")

                print(f"\nDecrypted Block {i + 1}:")
                print(f"Length: {len(block)} bytes")
                print(f"Block hex: {block.hex()}")
                print(f"Hash verified: True")

                current_hash = computed_hash
                decrypted_blocks.append(block)

            # Complete decryption
            decryptor.finalize()

            # Combine blocks and remove padding
            full_message = b''.join(decrypted_blocks)
            unpadded_message = AESGCMCipher.secure_unpad_block(full_message)
            decrypted = unpadded_message.decode()

            print("\nFinal decrypted message:")
            print(f"Message: {decrypted}")
            print("=== DECRYPTION COMPLETE ===\n")

            return decrypted

        except ValueError as ve:
            print(f"Decryption failed: {str(ve)}")
            raise  # Re-raise the error for proper handling
        except Exception as e:
            print(f"Unexpected error during decryption: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")