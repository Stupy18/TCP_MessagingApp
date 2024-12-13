from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class AESGCMCipher:
    """Handles AES-GCM encryption and decryption."""

    @staticmethod
    def encrypt(key, plaintext):
        """Encrypts a message using AES-GCM."""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext  # Concatenate IV, tag, and ciphertext

    @staticmethod
    def decrypt(key, encrypted_message):
        """Decrypts a message using AES-GCM."""
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
