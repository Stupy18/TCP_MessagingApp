from TLS.RoomHasher import RoomHasher


class RoomManager:
    """Manages chat rooms, passwords, and room membership"""

    def __init__(self, log_callback=None):
        self.rooms = {}  # room_name -> [client_sockets]
        self.room_settings = {}  # room_name -> {password, etc.}
        self.room_message_counts = {}  # room_name -> message_count
        self.log_callback = log_callback

    def create_room(self, room_name, password=None):
        """Create a new room with optional password"""
        if room_name not in self.rooms:
            self.rooms[room_name] = []

            # Initialize room settings dictionary for this room
            self.room_settings[room_name] = {}

            # Initialize message count for this room
            self.room_message_counts[room_name] = 0

            # If a password was provided during creation, store it
            if password:
                self.room_settings[room_name]["password"] = password

            # Initialize room hash key when room is created
            RoomHasher.create_room_key(room_name)
            self.log_message(f"Created new room with unique hash key: {room_name}")

            return True
        return False

    def delete_room(self, room_name):
        """Delete a room and clean up its settings"""
        if room_name in self.rooms:
            # Clean up room settings
            if room_name in self.room_settings:
                del self.room_settings[room_name]

            # Clean up message count
            if room_name in self.room_message_counts:
                del self.room_message_counts[room_name]

            # Clear the room
            del self.rooms[room_name]
            self.log_message(f"Room '{room_name}' has been deleted")
            return True
        return False

    def increment_room_message_count(self, room_name):
        """Increment the message count for a specific room"""
        if room_name in self.rooms:
            if room_name not in self.room_message_counts:
                self.room_message_counts[room_name] = 0
            self.room_message_counts[room_name] += 1

    def get_room_message_count(self, room_name):
        """Get the message count for a specific room"""
        return self.room_message_counts.get(room_name, 0)

    def room_exists(self, room_name):
        """Check if a room exists"""
        return room_name in self.rooms

    def validate_room_password(self, room_name, provided_password):
        """Validate password for a room"""
        if room_name not in self.rooms:
            return False

        # Check if the room has a password requirement
        if room_name in self.room_settings and "password" in self.room_settings[room_name]:
            stored_password = self.room_settings[room_name]["password"]
            return stored_password == provided_password

        # Room has no password, so any attempt is valid (including None)
        return True

    def add_client_to_room(self, client_socket, room_name):
        """Add a client to a room"""
        if room_name not in self.rooms:
            return False

        if client_socket not in self.rooms[room_name]:
            self.rooms[room_name].append(client_socket)
            return True
        return False

    def remove_client_from_room(self, client_socket, room_name):
        """Remove a client from a room"""
        if room_name in self.rooms and client_socket in self.rooms[room_name]:
            self.rooms[room_name].remove(client_socket)

            # Clean up empty rooms
            if not self.rooms[room_name]:
                self.delete_room(room_name)
                self.log_message(f"Room '{room_name}' has been closed (no active users)")

            return True
        return False

    def get_room_clients(self, room_name):
        """Get all clients in a room"""
        return self.rooms.get(room_name, [])

    def get_client_rooms(self, client_socket):
        """Get all rooms a client is in"""
        client_rooms = []
        for room_name, clients in self.rooms.items():
            if client_socket in clients:
                client_rooms.append(room_name)
        return client_rooms

    def remove_client_from_all_rooms(self, client_socket):
        """Remove a client from all rooms they're in"""
        rooms_to_remove = self.get_client_rooms(client_socket)
        for room_name in rooms_to_remove:
            self.remove_client_from_room(client_socket, room_name)

    def get_room_key_data(self, room_name):
        """Get the room key data for encryption"""
        if room_name in self.rooms:
            return RoomHasher.export_room_key(room_name)
        return None

    def get_all_rooms(self):
        """Get all rooms and their client counts"""
        return dict(self.rooms)

    def get_room_list(self):
        """Return a list of dictionaries containing room information"""
        room_list = []
        for room_name, clients in self.rooms.items():
            # Skip any special entries
            if "_settings" not in room_name:
                room_list.append({
                    "name": room_name,
                    "active_users": len(clients),
                    "message_count": self.get_room_message_count(room_name)  # Now returns actual count
                })

        return room_list

    def close_room(self, room_name):
        """Close a room (used by admin functions)"""
        if room_name in self.rooms:
            # Get clients before deletion for notification purposes
            room_clients = self.rooms[room_name][:]

            # Delete the room
            self.delete_room(room_name)

            return room_clients
        return []

    def get_room_count(self):
        """Get the total number of active rooms"""
        return len(self.rooms)

    def log_message(self, message):
        """Log messages using the provided callback"""
        if self.log_callback:
            self.log_callback(message)