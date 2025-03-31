import struct
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


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
        raise


def receive_encrypted_data(client_socket):
    """Helper function to receive encrypted data with length prefix"""
    try:
        # First receive the length prefix
        length_bytes = client_socket.recv(8)
        if not length_bytes:
            raise ConnectionError("Connection closed while receiving length")

        length = struct.unpack('>Q', length_bytes)[0]

        # Then receive the actual data
        data = b''
        remaining = length
        while remaining > 0:
            chunk = client_socket.recv(min(remaining, 4096))
            if not chunk:
                raise ConnectionError("Connection closed while receiving data")
            data += chunk
            remaining -= len(chunk)

        return data
    except Exception as e:
        raise


class AESCBCCipher:
    """A simplified AES-CBC cipher implementation that mimics AES-GCM interface but with CBC mode."""

    @staticmethod
    def encrypt(key, plaintext):
        """Encrypt data using AES-CBC with a format similar to the GCM version."""
        # Convert plaintext to bytes if it's a string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Generate a random IV
        iv = os.urandom(16)

        # Pad the plaintext to be a multiple of 16 bytes (AES block size)
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_length]) * padding_length

        # Create an AES-CBC cipher with the provided key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Return the IV + ciphertext as the encrypted message
        return iv + ciphertext

    @staticmethod
    def decrypt(key, encrypted_data):
        """Decrypt data that was encrypted with AES-CBC."""
        # Extract the IV from the first 16 bytes
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Create an AES-CBC cipher with the provided key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]

        # Return the plaintext as a string
        return plaintext.decode('utf-8', errors='replace')