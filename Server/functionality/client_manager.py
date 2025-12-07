from datetime import datetime


class ClientManager:
    """Manages client connections, tracking, and lifecycle"""

    def __init__(self, log_callback=None):
        self.clients = {}
        self.log_callback = log_callback
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_messages": 0,
            "start_time": None
        }

    def add_client(self, client_socket, client_address, symmetric_key, username=None):
        """Add a new client to the manager"""
        ip, port = client_address

        self.clients[client_socket] = {
            "address": client_address,
            "symmetric_key": symmetric_key,
            "username": username,
            "rooms": [],
            "connect_time": datetime.now()
        }

        # Update statistics
        self.stats["total_connections"] += 1
        self.stats["active_connections"] += 1

        self.log_message(f"Client connected: {username}@{ip}:{port}" if username else f"Client connected: {ip}:{port}")

    def remove_client(self, client_socket):
        """Remove a client from the manager"""
        if client_socket in self.clients:
            ip, port = self.clients[client_socket]["address"]

            # Update statistics
            self.stats["active_connections"] -= 1

            # Clean up client data
            del self.clients[client_socket]
            client_socket.close()

            self.log_message(f"Client disconnected: {ip}:{port}")

    def get_client_info(self, client_socket):
        """Get information about a specific client"""
        return self.clients.get(client_socket, None)

    def get_client_symmetric_key(self, client_socket):
        """Get the symmetric key for a client"""
        client_info = self.clients.get(client_socket)
        return client_info["symmetric_key"] if client_info else None

    def add_client_to_room(self, client_socket, room_name):
        """Add a client to a room"""
        if client_socket in self.clients:
            if room_name not in self.clients[client_socket]["rooms"]:
                self.clients[client_socket]["rooms"].append(room_name)

    def remove_client_from_room(self, client_socket, room_name):
        """Remove a client from a room"""
        if client_socket in self.clients:
            if room_name in self.clients[client_socket]["rooms"]:
                self.clients[client_socket]["rooms"].remove(room_name)

    def get_client_rooms(self, client_socket):
        """Get the list of rooms a client is in"""
        client_info = self.clients.get(client_socket)
        return client_info["rooms"] if client_info else []

    def get_all_clients(self):
        """Get all connected clients"""
        return dict(self.clients)

    def disconnect_client_by_address(self, ip, port):
        """Disconnect a client by its IP address and port"""
        for client_socket, client_data in list(self.clients.items()):
            if client_data["address"] == (ip, int(port)):
                self.remove_client(client_socket)
                return True
        return False

    def increment_message_count(self):
        """Increment the total message count"""
        self.stats["total_messages"] += 1

    def get_stats(self):
        """Get client manager statistics"""
        uptime = None
        if self.stats["start_time"]:
            uptime = datetime.now() - self.stats["start_time"]

        return {
            "total_connections": self.stats["total_connections"],
            "active_connections": self.stats["active_connections"],
            "total_messages": self.stats["total_messages"],
            "uptime": uptime
        }

    def set_start_time(self, start_time):
        """Set the server start time for uptime calculation"""
        self.stats["start_time"] = start_time

    def reset_stats(self):
        """Reset all statistics"""
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_messages": 0,
            "start_time": None
        }

    def get_client_list(self):
        """Return a list of dictionaries containing client information"""
        client_list = []
        for client_socket, client_data in self.clients.items():
            ip, port = client_data["address"]
            connected_time = datetime.now() - client_data.get("connect_time", datetime.now())
            rooms = client_data["rooms"]
            username = client_data.get("username", "Unknown")  # Get username

            client_list.append({
                "ip": ip,
                "port": port,
                "username": username,  # Add username to the list
                "connected_time": str(connected_time).split(".")[0],
                "rooms": rooms
            })

        return client_list

    def log_message(self, message):
        """Log messages using the provided callback"""
        if self.log_callback:
            self.log_callback(message)