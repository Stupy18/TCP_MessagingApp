class RoomManager:
    """Handles room operations and state management"""

    def __init__(self, connection_manager):
        self.connection_manager = connection_manager
        self.rooms = []

    def join_room(self, room_name, password=None):
        """Send a join room request to the server"""
        try:
            if room_name not in self.rooms:
                # Format the join command with an optional password
                command = f"/join {room_name}"
                if password:
                    command += f" password={password}"

                # Send join request to the server
                self.connection_manager.send_encrypted_message(command)

                # We'll return success for sending the request, not for joining the room
                # The actual room joining will be confirmed when we receive the room key
                return True, "Join request sent"

            return False, "Already in room"
        except Exception as e:
            return False, str(e)

    def leave_room(self, room_name):
        """Leave a room and notify the server"""
        try:
            if room_name in self.rooms:
                self.rooms.remove(room_name)
                self.connection_manager.send_encrypted_message(f"/leave {room_name}")
                return True, room_name
            return False, "Not in room"
        except Exception as e:
            return False, str(e)

    def send_message_to_room(self, message, room_name, username):
        """Send a message to a specific room"""
        try:
            if not self.rooms:
                return False, "Please join a room first"

            if room_name is None and len(self.rooms) > 0:
                room_name = self.rooms[0]  # Default to first room if none specified

            if room_name not in self.rooms:
                return False, f"Not in room {room_name}"

            # Format message with room information
            formatted_message = f"/msg {room_name} {username}: {message}"

            self.connection_manager.send_encrypted_message(formatted_message)

            # Return the message as it should appear
            return True, f"{username}: {message}"
        except Exception as e:
            return False, str(e)

    def get_rooms(self):
        """Get the list of joined rooms"""
        return self.rooms.copy()

    def is_in_room(self, room_name):
        """Check if currently in a specific room"""
        return room_name in self.rooms

    def add_room(self, room_name):
        """Add a room to the joined rooms list (called when room key is received)"""
        if room_name not in self.rooms:
            self.rooms.append(room_name)

    def remove_room(self, room_name):
        """Remove a room from the joined rooms list"""
        if room_name in self.rooms:
            self.rooms.remove(room_name)

    def clear_rooms(self):
        """Clear all rooms (called on disconnect)"""
        self.rooms.clear()