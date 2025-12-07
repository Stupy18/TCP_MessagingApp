from Client.functionality.connection_manager import ConnectionManager
from Client.functionality.client_handshake import ClientHandshake
from Client.functionality.message_handler import MessageHandler
from Client.functionality.room_manager import RoomManager


class ChatClient:
    """Main chat client orchestrator using modular components"""

    def __init__(self, message_callback=None, room_closed_callback=None):
        # Initialize components
        self.connection_manager = ConnectionManager()
        self.handshake = ClientHandshake(self.connection_manager)
        self.message_handler = MessageHandler(self.connection_manager)
        self.room_manager = RoomManager(self.connection_manager)

        # Client state
        self.username = None
        self.message_callback = message_callback
        self.room_closed_callback = room_closed_callback

    def connect_to_server(self, server_ip, server_port, username):
        """Connect to the chat server and perform authentication"""
        try:
            # Establish socket connection
            success, message = self.connection_manager.connect_to_server(server_ip, server_port)
            if not success:
                return False, message

            # Perform key exchange
            success = self.handshake.perform_key_exchange(username)
            if not success or self.connection_manager.symmetric_key is None:
                raise ConnectionError("Key exchange failed or no symmetric key generated")

            # Set connection state
            self.username = username
            self.connection_manager.set_connected(True)
            return True, f"Connected to {server_ip}:{server_port}"

        except Exception as e:
            return False, str(e)

    def send_message(self, message, room_name=None):
        """Send a message to a room"""
        return self.room_manager.send_message_to_room(message, room_name, self.username)

    def join_room(self, room_name, password=None):
        """Join a chat room"""
        return self.room_manager.join_room(room_name, password)

    def leave_room(self, room_name):
        """Leave a chat room"""
        return self.room_manager.leave_room(room_name)

    def disconnect(self):
        """Disconnect from the server"""
        self.connection_manager.disconnect()
        self.room_manager.clear_rooms()

    def listen_for_messages(self):
        """Listen for incoming messages from the server"""
        try:
            while self.connection_manager.is_connected():
                try:
                    self.message_handler.process_incoming_message(
                        self.room_manager.rooms,
                        self.message_callback,
                        self.room_closed_callback
                    )
                except ConnectionError:
                    # Connection was closed
                    self.connection_manager.set_connected(False)
                    if self.message_callback:
                        self.message_callback("Connection to server lost")
                    break
                except Exception as e:
                    # Log the error but don't break the loop for recoverable errors
                    print(f"Error processing message: {str(e)}")
                    # Continue the loop to try receiving more messages

        except Exception as e:
            print(f"Error in listen_for_messages: {str(e)}")
            if self.connection_manager.is_connected():
                self.connection_manager.set_connected(False)
                # Try to notify the user via message callback if available
                if self.message_callback:
                    try:
                        self.message_callback(f"Connection error: {str(e)}")
                    except:
                        pass  # Fail silently if we can't send the message

    def encrypt_message(self, message):
        """Encrypt a message (for backward compatibility)"""
        return self.message_handler.encrypt_message(message)

    # Properties for backward compatibility
    @property
    def connected(self):
        """Check if connected to server"""
        return self.connection_manager.is_connected()

    @property
    def rooms(self):
        """Get list of joined rooms"""
        return self.room_manager.get_rooms()

    @property
    def symmetric_key(self):
        """Get the symmetric key"""
        return self.connection_manager.symmetric_key

    # Private method for backward compatibility
    def _extract_room_and_verify_message(self, message):
        """Extract room and verify message (backward compatibility)"""
        return self.message_handler.extract_room_and_verify_message(
            message,
            self.room_manager.rooms
        )