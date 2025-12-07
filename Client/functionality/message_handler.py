from TLS.AES_GCM_CYPHER import AESGCMCipher
from TLS.RoomHasher import RoomHasher


class MessageHandler:
    """Handles message encryption, decryption, and processing"""

    def __init__(self, connection_manager):
        self.connection_manager = connection_manager

    def encrypt_message(self, message):
        """Encrypt a message for transmission"""
        try:
            symmetric_key = self.connection_manager.symmetric_key

            if symmetric_key is None:
                raise ValueError("No symmetric key available - please ensure you're connected")

            if not isinstance(symmetric_key, bytes):
                raise ValueError(f"Invalid symmetric key type: {type(symmetric_key)}")

            if len(symmetric_key) != 32:
                raise ValueError(f"Invalid symmetric key length: {len(symmetric_key)} bytes")

            encrypted_message = AESGCMCipher.encrypt(symmetric_key, message)
            # Return the encrypted message directly without base64 encoding
            return encrypted_message
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def extract_room_and_verify_message(self, message, client_rooms):
        """
        Extracts the room from a message and verifies its room-specific hash
        """
        try:
            # Handle messages without a pipe (not hashed)
            if "|" not in message:
                return message, None

            # For messages with a hash
            if message.startswith("[") and "]" in message:
                room_end = message.find("]")
                room_name = message[1:room_end].strip()

                # Only try verification if we have the room key
                if room_name in RoomHasher.room_keys:
                    verified_message = RoomHasher.verify_and_extract_message(message, room_name)
                    if verified_message:
                        return verified_message, room_name

                # If we don't have the key or verification fails, try to extract the original message
                parts = message.split("|", 1)
                if len(parts) == 2:
                    return parts[0], room_name  # Return the message part without the hash

            # For system messages that are hashed
            elif message.startswith("[SYSTEM]") and "|" in message:
                # Try all rooms the client is in
                for room_name in client_rooms:
                    if room_name in RoomHasher.room_keys:
                        verified = RoomHasher.verify_and_extract_message(message, room_name)
                        if verified:
                            return verified, room_name

                # If no verification, return just the message part
                parts = message.split("|", 1)
                if len(parts) == 2:
                    return parts[0], None

            # Default fallback - return the original message
            return message, None

        except Exception as e:
            print(f"Error processing message hash: {str(e)}")
            return message, None

    def process_incoming_message(self, client_rooms, message_callback, room_closed_callback):
        """Process a single incoming message and handle different message types"""
        try:
            decrypted_message = self.connection_manager.receive_encrypted_message()

            # Handle room key messages - this is confirmation that we joined successfully
            if decrypted_message.startswith("/room_key "):
                parts = decrypted_message.split(" ", 2)
                if len(parts) == 3:
                    _, room_name, key_data = parts
                    success = RoomHasher.import_room_key(room_name, key_data)
                    # Add the room to our list ONLY when we get the room key
                    if room_name not in client_rooms:
                        client_rooms.append(room_name)
                    if success and message_callback:
                        message_callback(f"Received encryption key for room: {room_name}")
                return

            # Handle error messages (like wrong password)
            if decrypted_message.startswith("/error "):
                error_message = decrypted_message[7:]  # Remove "/error " prefix
                if message_callback:
                    # Make the error message more user-friendly
                    formatted_error = f"Error: {error_message}"
                    message_callback(formatted_error)
                return

            # Handle room closure messages
            if decrypted_message.startswith("/room_closed "):
                room_name = decrypted_message.split(" ", 1)[1].strip()
                if room_name in client_rooms:
                    client_rooms.remove(room_name)
                    if message_callback:
                        message_callback(f"Room '{room_name}' has been closed by the server.")
                    # Call the room_closed_callback to update the GUI
                    if room_closed_callback:
                        room_closed_callback(room_name)
                return

            # Handle regular messages
            verified_message, room = self.extract_room_and_verify_message(decrypted_message, client_rooms)
            if message_callback:
                message_callback(verified_message)

        except ConnectionError:
            # Connection was closed
            self.connection_manager.set_connected(False)
            if message_callback:
                message_callback("Connection to server lost")
            raise
        except Exception as e:
            # Log the error but don't break the loop for recoverable errors
            print(f"Error processing message: {str(e)}")
            # Continue the loop to try receiving more messages