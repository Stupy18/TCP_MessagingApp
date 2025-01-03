from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.padding import PKCS7


class AESGCMCipher:
    BLOCK_SIZE = 16  # AES block size in bytes

    @staticmethod
    def pad_data(data):
        """Pad data to fixed block size using PKCS7."""
        padder = PKCS7(AESGCMCipher.BLOCK_SIZE * 8).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        return padded_data

    @staticmethod
    def unpad_data(padded_data):
        """Remove PKCS7 padding."""
        unpadder = PKCS7(AESGCMCipher.BLOCK_SIZE * 8).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()
        return data

    @staticmethod
    def encrypt(key, plaintext):
        """Encrypts a message using AES-GCM with fixed block size."""
        # Convert plaintext to bytes if it's a string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        # Pad the plaintext to fixed block size
        padded_data = AESGCMCipher.pad_data(plaintext)

        # Generate IV and HMAC
        iv = os.urandom(12)
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(padded_data)
        hmac_value = h.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return fixed format: IV(12) + HMAC(32) + TAG(16) + CIPHERTEXT
        return iv + hmac_value + encryptor.tag + ciphertext

    @staticmethod
    def decrypt(key, encrypted_message):
        """Decrypts a message using AES-GCM with fixed block size."""
        # Split message into components
        iv = encrypted_message[:12]
        hmac_value = encrypted_message[12:44]  # 32 bytes HMAC
        tag = encrypted_message[44:60]  # 16 bytes tag
        ciphertext = encrypted_message[60:]

        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Verify HMAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(padded_plaintext)
        h.verify(hmac_value)

        # Unpad and return
        plaintext = AESGCMCipher.unpad_data(padded_plaintext)
        return plaintext.decode()
