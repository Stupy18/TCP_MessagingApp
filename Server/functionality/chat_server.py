from datetime import datetime
from TLS.AES_GCM_CYPHER import receive_encrypted_data, AESGCMCipher

from Server.functionality.server_core import ServerCore
from Server.functionality.client_manager import ClientManager
from Server.functionality.room_manager import RoomManager
from Server.functionality.message_broadcaster import MessageBroadcaster
from Server.functionality.server_handshake import ServerHandshake


class ChatServer:

    def __init__(self, log_callback=None):
        # Initialize components
        self.server_core = ServerCore(log_callback)
        self.client_manager = ClientManager(log_callback)
        self.room_manager = RoomManager(log_callback)
        self.message_broadcaster = MessageBroadcaster(self.client_manager, self.room_manager, log_callback)
        self.handshake = ServerHandshake()

        # Set the client handler in server core
        self.server_core.set_client_handler(self.handle_client)

        # Legacy properties for backward compatibility
        self.log_callback = log_callback

    def start(self, host, port):
        """Start the chat server"""
        success, message = self.server_core.start(host, port)
        if success:
            self.client_manager.set_start_time(datetime.now())
        return success, message

    def stop(self):
        """Stop the chat server"""
        # Disconnect all clients first
        for client_socket in list(self.client_manager.get_all_clients().keys()):
            self.disconnect_client(client_socket)

        # Reset statistics
        self.client_manager.reset_stats()

        return self.server_core.stop()

    def handle_client(self, client_socket, client_address):
        """Handle a client connection (called by server_core)"""
        try:
            # Perform handshake
            symmetric_key, username = self.handshake.perform_key_exchange(client_socket, client_address)

            # Add client to manager
            self.client_manager.add_client(client_socket, client_address, symmetric_key, username)

            # Handle client messages
            while self.server_core.is_server_running():
                try:
                    encrypted_data = receive_encrypted_data(client_socket)
                    decrypted_message = AESGCMCipher.decrypt(symmetric_key, encrypted_data)
                    self.client_manager.increment_message_count()

                    if decrypted_message.startswith("/join "):
                        self.join_room(client_socket, decrypted_message)
                    elif decrypted_message.startswith("/leave "):
                        room_name = decrypted_message.split(" ", 1)[1].strip()
                        self.leave_room(client_socket, room_name)
                    elif decrypted_message.startswith("/msg "):
                        # New message format: "/msg room_name username: message"
                        parts = decrypted_message.split(" ", 2)
                        if len(parts) >= 3:
                            room_name = parts[1]
                            message_content = parts[2]
                            self.message_broadcaster.broadcast_to_room(message_content, client_socket, room_name)
                    else:
                        # Legacy support for old message format
                        self.message_broadcaster.broadcast_legacy(decrypted_message, client_socket)

                except Exception as e:
                    client_info = self.client_manager.get_client_info(client_socket)
                    if client_info:
                        ip, port = client_info["address"]
                        self.log_message(f"Error with client {ip}:{port}: {str(e)}")
                    break

        finally:
            self.disconnect_client(client_socket)

    def join_room(self, client_socket, room_data):
        """Handle a client joining a room"""
        # Parse room data which can now contain password info
        parts = room_data.split()
        room_name = parts[1].strip()

        # Check if this is a password-protected room request
        room_password = None
        if len(parts) > 2 and parts[2].startswith("password="):
            room_password = parts[2][9:].strip()  # Extract password after "password="

        # Validate password if room exists
        if self.room_manager.room_exists(room_name):
            if not self.room_manager.validate_room_password(room_name, room_password):
                # Send error message
                error_message = f"Incorrect password for room '{room_name}'"
                self.message_broadcaster.send_error_to_client(client_socket, error_message)
                return  # Exit without joining

        # Create room if it doesn't exist
        if not self.room_manager.room_exists(room_name):
            self.room_manager.create_room(room_name, room_password)

        # Add client to the room
        if self.room_manager.add_client_to_room(client_socket, room_name):
            self.client_manager.add_client_to_room(client_socket, room_name)

            # Send room key to the client for message verification
            self.message_broadcaster.send_room_key_to_client(client_socket, room_name)

            client_info = self.client_manager.get_client_info(client_socket)
            if client_info:
                ip, port = client_info["address"]
                self.log_message(f"Client {ip}:{port} joined room: {room_name}")

                # Notify all clients in the room about the new member
                join_message = f"User {ip}:{port} has joined the room."
                self.message_broadcaster.broadcast_system_message(join_message, room_name)

    def leave_room(self, client_socket, room_name):
        """Handle a client leaving a room"""
        if self.room_manager.remove_client_from_room(client_socket, room_name):
            self.client_manager.remove_client_from_room(client_socket, room_name)

            client_info = self.client_manager.get_client_info(client_socket)
            if client_info:
                ip, port = client_info["address"]
                self.log_message(f"Client {ip}:{port} left room: {room_name}")

                # Notify remaining clients
                leave_message = f"User {ip}:{port} has left the room."
                self.message_broadcaster.broadcast_system_message(leave_message, room_name)

    def disconnect_client(self, client_socket):
        """Disconnect a client and clean up"""
        # Remove client from all rooms
        self.room_manager.remove_client_from_all_rooms(client_socket)

        # Remove client from manager
        self.client_manager.remove_client(client_socket)

    def get_stats(self):
        """Return server statistics"""
        client_stats = self.client_manager.get_stats()
        server_info = self.server_core.get_server_info()

        return {
            "total_connections": client_stats["total_connections"],
            "active_connections": client_stats["active_connections"],
            "total_messages": client_stats["total_messages"],
            "active_rooms": self.room_manager.get_room_count(),
            "uptime": client_stats["uptime"],
            "host": server_info["host"],
            "port": server_info["port"],
            "running": server_info["running"]
        }

    def get_client_list(self):
        """Return a list of client information"""
        return self.client_manager.get_client_list()

    def get_room_list(self):
        """Return a list of room information"""
        return self.room_manager.get_room_list()

    def disconnect_client_by_address(self, ip, port):
        """Disconnect a client by IP address and port"""
        return self.client_manager.disconnect_client_by_address(ip, port)

    def close_room(self, room_name):
        """Close a room and notify all clients"""
        if self.room_manager.room_exists(room_name):
            # Get clients before closing for notification
            room_clients = self.room_manager.get_room_clients(room_name)

            # Notify clients about room closure
            self.message_broadcaster.notify_room_closure(room_name, room_clients)

            # Remove clients from the room in client manager
            for client_socket in room_clients:
                self.client_manager.remove_client_from_room(client_socket, room_name)

            # Close the room
            self.room_manager.close_room(room_name)

            self.log_message(f"Room '{room_name}' has been closed by admin")
            return True
        return False

    def log_message(self, message):
        """Log a message using the server core"""
        self.server_core.log_message(message)

    # Legacy properties for backward compatibility
    @property
    def host(self):
        return self.server_core.host

    @property
    def port(self):
        return self.server_core.port

    @property
    def is_running(self):
        return self.server_core.is_server_running()

    @property
    def clients(self):
        return self.client_manager.get_all_clients()

    @property
    def rooms(self):
        return self.room_manager.get_all_rooms()

    # Legacy method for backward compatibility
    def perform_key_exchange(self, client_socket, client_address=None):
        """Legacy method - delegates to handshake component"""
        return self.handshake.perform_key_exchange(client_socket, client_address)