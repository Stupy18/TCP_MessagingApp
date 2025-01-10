import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def send_encrypted_data(client_socket, data):
    """Helper function to send encrypted data with length prefix"""
    try:
        # Send length prefix first
        length = len(data)
        length_bytes = struct.pack('>Q', length)
        client_socket.sendall(length_bytes)

        # Then send the actual data
        client_socket.sendall(data)
    except Exception as e:
        print(f"Debug - Send encrypted data error: {str(e)}")
        raise


def receive_encrypted_data(client_socket):
    """Helper function to receive encrypted data with length prefix"""
    try:
        # First receive the length prefix
        length_bytes = client_socket.recv(8)
        if not length_bytes:
            raise ConnectionError("Connection closed while receiving length")

        length = struct.unpack('>Q', length_bytes)[0]
        print(f"Debug - Expected message length: {length}")

        # Then receive the actual data
        data = b''
        remaining = length
        while remaining > 0:
            chunk = client_socket.recv(min(remaining, 4096))
            if not chunk:
                raise ConnectionError("Connection closed while receiving data")
            data += chunk
            remaining -= len(chunk)

        print(f"Debug - Received complete message of length: {len(data)}")
        return data
    except Exception as e:
        print(f"Debug - Receive encrypted data error: {str(e)}")
        raise


class AESGCMCipher:
    """Handles AES-GCM encryption and decryption with fixed-size blocks and record layer padding."""

    # Define constants
    BLOCK_SIZE = 1024  # Fixed block size for the record layer
    LENGTH_SIZE = 8  # Size of the length field in bytes
    HEADER_SIZE = 20  # IV(12) + Length(8) bytes
    TAG_SIZE = 16  # GCM authentication tag size

    @staticmethod
    def ensure_bytes(key):
        """Ensures the key is in the correct bytes format."""
        if isinstance(key, (bytes, bytearray, memoryview)):
            return bytes(key)
        raise ValueError("Key must be bytes-like object")

    @staticmethod
    def pad_record(message):
        """
        Applies record layer padding to ensure fixed block size.
        Format: [original_length (8 bytes)][message][padding]
        """
        try:
            # Ensure message is a string and encode it
            if not isinstance(message, str):
                message = str(message)

            message_bytes = message.encode('utf-8', errors='replace')
            original_length = len(message_bytes)
            print(f"Debug - Padding message of length: {original_length}")

            # Calculate required padding
            total_size = AESGCMCipher.HEADER_SIZE + original_length + AESGCMCipher.TAG_SIZE
            padding_size = (AESGCMCipher.BLOCK_SIZE - (total_size % AESGCMCipher.BLOCK_SIZE)) % AESGCMCipher.BLOCK_SIZE
            print(f"Debug - Adding padding of size: {padding_size}")

            # Create padding bytes (using PKCS7-style padding with valid bytes)
            padding = bytes([padding_size & 0xFF] * padding_size)

            # Combine length, message, and padding
            length_bytes = struct.pack(">Q", original_length)  # 8 bytes for length
            padded_record = length_bytes + message_bytes + padding
            print(f"Debug - Final padded record length: {len(padded_record)}")
            return padded_record

        except Exception as e:
            print(f"Debug - Padding error: {str(e)}")
            raise ValueError(f"Failed to pad record: {str(e)}")

    @staticmethod
    def unpad_record(padded_data):
        """
        Removes record layer padding and returns original message.
        """
        try:
            print(f"Debug - Unpadding data of length: {len(padded_data)}")

            # Extract original length
            original_length = struct.unpack(">Q", padded_data[:AESGCMCipher.LENGTH_SIZE])[0]
            print(f"Debug - Original message length from header: {original_length}")

            # Validate length
            if original_length > len(padded_data) - AESGCMCipher.LENGTH_SIZE:
                raise ValueError(f"Invalid message length in padded data: {original_length}")

            # Extract message using the original length
            message_bytes = padded_data[AESGCMCipher.LENGTH_SIZE:AESGCMCipher.LENGTH_SIZE + original_length]
            print(f"Debug - Extracted message length: {len(message_bytes)}")

            return message_bytes.decode('utf-8', errors='replace')

        except Exception as e:
            print(f"Debug - Unpadding error: {str(e)}")
            raise ValueError(f"Failed to unpad record: {str(e)}")

    @staticmethod
    def encrypt(key, plaintext):
        """
        Encrypts a message using AES-GCM with fixed block size.
        Format: [IV (12 bytes)][Encrypted(length + message + padding)][Tag (16 bytes)]
        """
        try:
            print(f"Debug - Encrypting message: {plaintext}")
            # Ensure key is in correct format
            key = AESGCMCipher.ensure_bytes(key)

            # Validate key length
            if len(key) != 32:  # We're using AES-256
                raise ValueError(f"Invalid key length: {len(key)} bytes (expected 32)")

            # Generate IV
            iv = os.urandom(12)
            print(f"Debug - Generated IV length: {len(iv)}")

            # Initialize cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Pad the record
            padded_record = AESGCMCipher.pad_record(plaintext)
            print(f"Debug - Padded record length: {len(padded_record)}")

            # Encrypt the padded record
            ciphertext = encryptor.update(padded_record) + encryptor.finalize()
            print(f"Debug - Ciphertext length: {len(ciphertext)}")

            # Combine IV, encrypted data, and authentication tag
            encrypted_message = iv + ciphertext + encryptor.tag
            print(f"Debug - Final encrypted message length: {len(encrypted_message)}")

            # Verify block size
            if len(encrypted_message) % AESGCMCipher.BLOCK_SIZE != 0:
                raise ValueError(
                    f"Encrypted message length {len(encrypted_message)} is not a multiple of block size {AESGCMCipher.BLOCK_SIZE}")

            return encrypted_message

        except Exception as e:
            print(f"Debug - Encryption error: {str(e)}")
            raise ValueError(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt(key, encrypted_message):
        """
        Decrypts a message using AES-GCM and removes padding.
        """
        try:
            print(f"Debug - Decrypting message of length: {len(encrypted_message)}")

            # Ensure key is in correct format
            key = AESGCMCipher.ensure_bytes(key)

            # Validate key length
            if len(key) != 32:
                raise ValueError(f"Invalid key length: {len(key)} bytes")

            if len(encrypted_message) < AESGCMCipher.HEADER_SIZE + AESGCMCipher.TAG_SIZE:
                raise ValueError(f"Encrypted message too short: {len(encrypted_message)} bytes")

            # Extract IV and tag
            iv = encrypted_message[:12]
            tag = encrypted_message[-AESGCMCipher.TAG_SIZE:]
            ciphertext = encrypted_message[12:-AESGCMCipher.TAG_SIZE]

            print(f"Debug - IV length: {len(iv)}")
            print(f"Debug - Tag length: {len(tag)}")
            print(f"Debug - Ciphertext length: {len(ciphertext)}")

            # Initialize cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt the message
            padded_record = decryptor.update(ciphertext) + decryptor.finalize()
            print(f"Debug - Decrypted padded record length: {len(padded_record)}")

            # Remove padding and return original message
            return AESGCMCipher.unpad_record(padded_record)

        except Exception as e:
            print(f"Debug - Decryption error: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")
