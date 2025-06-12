from TLS.AES_GCM_CYPHER import AESGCMCipher, send_encrypted_data
from TLS.RoomHasher import RoomHasher


class MessageBroadcaster:
    """Handles message distribution and broadcasting to rooms"""

    def __init__(self, client_manager, room_manager, log_callback=None):
        self.client_manager = client_manager
        self.room_manager = room_manager
        self.log_callback = log_callback

    def broadcast_to_room(self, message, sender_socket, room_name):
        """Broadcast a message to all clients in a specific room"""
        try:
            # Check if room exists and client is in it
            if not self.room_manager.room_exists(room_name):
                return

            room_clients = self.room_manager.get_room_clients(room_name)
            if sender_socket not in room_clients:
                return

            sender_info = self.client_manager.get_client_info(sender_socket)
            if not sender_info:
                return

            sender_ip, sender_port = sender_info["address"]

            # Create room-specific hash for the message
            formatted_message = f"[{room_name}] {message}"
            room_hashed_message = RoomHasher.hash_message(formatted_message, room_name)

            self.log_message(f"Message in {room_name} from {sender_ip}:{sender_port}: {message}")

            # Increment message count for this room
            self.room_manager.increment_room_message_count(room_name)

            # Send to other clients in this room only
            for client_socket in room_clients:
                if client_socket != sender_socket:
                    try:
                        symmetric_key = self.client_manager.get_client_symmetric_key(client_socket)
                        if symmetric_key:
                            encrypted_message = AESGCMCipher.encrypt(symmetric_key, room_hashed_message)
                            send_encrypted_data(client_socket, encrypted_message)
                    except Exception as e:
                        self.log_message(f"Error broadcasting message: {str(e)}")

        except Exception as e:
            self.log_message(f"Error in room broadcast: {str(e)}")

    def broadcast_system_message(self, message, room_name):
        """Broadcast a system message to all clients in a room"""
        system_message = f"[SYSTEM] {message}"

        # Apply room-specific hashing to system messages too
        hashed_system_message = RoomHasher.hash_message(system_message, room_name)

        # Increment message count for system messages too
        if self.room_manager.room_exists(room_name):
            self.room_manager.increment_room_message_count(room_name)

            room_clients = self.room_manager.get_room_clients(room_name)
            for client_socket in room_clients:
                try:
                    symmetric_key = self.client_manager.get_client_symmetric_key(client_socket)
                    if symmetric_key:
                        encrypted_message = AESGCMCipher.encrypt(symmetric_key, hashed_system_message)
                        send_encrypted_data(client_socket, encrypted_message)
                except Exception as e:
                    self.log_message(f"Error sending system message: {str(e)}")

    def broadcast_legacy(self, message, sender_socket):
        """Legacy broadcast method for backward compatibility"""
        try:
            sender_info = self.client_manager.get_client_info(sender_socket)
            if not sender_info:
                return

            sender_ip, sender_port = sender_info["address"]
            sender_rooms = self.client_manager.get_client_rooms(sender_socket)

            # Extract username from the message (assuming format "Username: message")
            username = message.split(":", 1)[0]
            message_content = message.split(":", 1)[1] if ":" in message else message

            for room_name in sender_rooms:
                if not self.room_manager.room_exists(room_name):
                    continue  # Skip if room doesn't exist anymore

                # Create a cleaner formatted message with just the username
                formatted_message = f"[{room_name}] {username}:{message_content}"
                room_hashed_message = RoomHasher.hash_message(formatted_message, room_name)

                self.log_message(f"Message in {room_name} from {sender_ip}:{sender_port}: {message}")

                # Increment message count for this room
                self.room_manager.increment_room_message_count(room_name)

                # Only broadcast to clients that are actually in this room
                room_clients = self.room_manager.get_room_clients(room_name)
                for client_socket in room_clients:
                    if client_socket != sender_socket:
                        try:
                            symmetric_key = self.client_manager.get_client_symmetric_key(client_socket)
                            if symmetric_key:
                                encrypted_message = AESGCMCipher.encrypt(symmetric_key, room_hashed_message)
                                send_encrypted_data(client_socket, encrypted_message)
                        except Exception as e:
                            self.log_message(f"Error broadcasting message: {str(e)}")

        except Exception as e:
            self.log_message(f"Error in broadcast: {str(e)}")

    def send_encrypted_message_to_client(self, client_socket, message):
        """Send an encrypted message to a specific client"""
        try:
            symmetric_key = self.client_manager.get_client_symmetric_key(client_socket)
            if symmetric_key:
                encrypted_message = AESGCMCipher.encrypt(symmetric_key, message)
                send_encrypted_data(client_socket, encrypted_message)
                return True
        except Exception as e:
            self.log_message(f"Error sending message to client: {str(e)}")
        return False

    def send_room_key_to_client(self, client_socket, room_name):
        """Send room encryption key to a client"""
        room_key_data = self.room_manager.get_room_key_data(room_name)
        if room_key_data:
            key_message = f"/room_key {room_name} {room_key_data}"
            return self.send_encrypted_message_to_client(client_socket, key_message)
        return False

    def send_error_to_client(self, client_socket, error_message):
        """Send an error message to a client"""
        formatted_error = f"/error {error_message}"
        return self.send_encrypted_message_to_client(client_socket, formatted_error)

    def notify_room_closure(self, room_name, client_sockets):
        """Notify clients that a room is being closed"""
        close_message = f"Room '{room_name}' is being closed by the server."
        self.broadcast_system_message(close_message, room_name)

        # Send a special command to tell clients to remove the room
        remove_command = f"/room_closed {room_name}"
        for client_socket in client_sockets:
            self.send_encrypted_message_to_client(client_socket, remove_command)

    def log_message(self, message):
        """Log messages using the provided callback"""
        if self.log_callback:
            self.log_callback(message)