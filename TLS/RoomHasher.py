import hashlib
import hmac
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


class RoomHasher:
    """
    Provides room-specific message hashing capabilities to add an extra layer
    of security based on room context.
    """
    # Store room-specific keys (room_name -> key)
    room_keys = {}

    @classmethod
    def create_room_key(cls, room_name, salt=None):
        """
        Creates a unique cryptographic key for a room based on its name.
        Uses PBKDF2 to derive a secure key from the room name.

        Args:
            room_name (str): The name of the room
            salt (bytes, optional): Custom salt for key derivation

        Returns:
            bytes: The derived room key
        """
        if not salt:
            # Generate a random salt if not provided
            salt = os.urandom(16)

        # Create a key derivation function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=salt,
            iterations=100000,  # High iteration count for security
            backend=default_backend()
        )

        # Derive key from room name
        key = kdf.derive(room_name.encode('utf-8'))

        # Store the key for this room
        cls.room_keys[room_name] = {
            'key': key,
            'salt': salt
        }

        return key

    @classmethod
    def get_room_key(cls, room_name):
        """
        Retrieves the key for a specific room, creating it if it doesn't exist.

        Args:
            room_name (str): The name of the room

        Returns:
            bytes: The room key
        """
        if room_name not in cls.room_keys:
            return cls.create_room_key(room_name)

        return cls.room_keys[room_name]['key']

    @classmethod
    def hash_message(cls, message, room_name):
        """
        Adds a room-specific hash to a message.

        Args:
            message (str): The message to hash
            room_name (str): The room name to use for hashing

        Returns:
            str: Message with room-specific hash appended
        """
        # Get or create room key
        room_key = cls.get_room_key(room_name)

        # Create HMAC using the room key
        h = hmac.new(room_key, message.encode('utf-8'), hashlib.sha256)
        message_hmac = h.hexdigest()

        # Format: message|HMAC
        return f"{message}|{message_hmac}"

    @classmethod
    def verify_and_extract_message(cls, hashed_message, room_name):
        """
        Verifies the room-specific hash of a message and extracts the original message.

        Args:
            hashed_message (str): The message with hash
            room_name (str): The room name used for hashing

        Returns:
            str or None: The original message if hash is valid, None otherwise
        """
        try:
            # Split message and hash
            parts = hashed_message.split('|')
            if len(parts) != 2:
                return None

            message, message_hmac = parts

            # Get room key
            room_key = cls.get_room_key(room_name)

            # Compute expected HMAC
            h = hmac.new(room_key, message.encode('utf-8'), hashlib.sha256)
            expected_hmac = h.hexdigest()

            # Verify HMAC
            if hmac.compare_digest(message_hmac, expected_hmac):
                return message
            else:
                return None
        except Exception as e:
            print(f"Error verifying message: {str(e)}")
            return None

    @classmethod
    def export_room_key(cls, room_name):
        """
        Exports the room key and salt as a base64 encoded string for sharing.

        Args:
            room_name (str): The name of the room

        Returns:
            str: Base64 encoded room key data
        """
        if room_name not in cls.room_keys:
            cls.create_room_key(room_name)

        data = {
            'key': base64.b64encode(cls.room_keys[room_name]['key']).decode('utf-8'),
            'salt': base64.b64encode(cls.room_keys[room_name]['salt']).decode('utf-8')
        }

        return base64.b64encode(f"{data['key']}:{data['salt']}".encode('utf-8')).decode('utf-8')

    @classmethod
    def import_room_key(cls, room_name, key_data):
        """
        Imports a room key from a base64 encoded string.

        Args:
            room_name (str): The name of the room
            key_data (str): Base64 encoded room key data

        Returns:
            bool: True if import was successful
        """
        try:
            decoded = base64.b64decode(key_data).decode('utf-8')
            key_b64, salt_b64 = decoded.split(':')

            key = base64.b64decode(key_b64)
            salt = base64.b64decode(salt_b64)

            cls.room_keys[room_name] = {
                'key': key,
                'salt': salt
            }

            return True
        except Exception as e:
            print(f"Error importing room key: {str(e)}")
            return False