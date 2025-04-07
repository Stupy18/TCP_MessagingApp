import socket
import threading
import time
from datetime import datetime
from cryptography.hazmat.primitives import serialization

from TLS.DigitalSigniture import DigitalSignature
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.AES_GCM_CYPHER import AESGCMCipher, send_encrypted_data, receive_encrypted_data
from TLS.OpenSSlCertHandler import OpenSSLCertHandler
from TLS.RoomHasher import RoomHasher


class ChatServer:
    def __init__(self, log_callback=None):
        self.host = None
        self.port = 8080
        self.server_socket = None
        self.clients = {}
        self.rooms = {}
        self.is_running = False
        self.ecdsa_private_key, self.ecdsa_public_key = DigitalSignature.generate_keypair()
        self.private_key = None
        self.public_key = None
        self.signing_private = None
        self.signing_public = None
        self.accept_thread = None
        self.log_callback = log_callback
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_messages": 0,
            "start_time": None
        }

    def log_message(self, message):
        """Log messages and call the callback if provided"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        print(formatted_message)
        if self.log_callback:
            self.log_callback(formatted_message)

    def start(self, host, port):
        try:
            self.host = host
            self.port = int(port)

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(50)

            self.is_running = True
            self.stats["start_time"] = datetime.now()

            self.log_message(f"Server started at {self.host}:{self.port}")

            # Create a separate thread for accepting connections
            self.accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            self.accept_thread.start()

            return True, "Server started successfully"

        except Exception as e:
            error_msg = f"Failed to start server: {str(e)}"
            self.log_message(error_msg)
            return False, error_msg

    def stop(self):
        self.is_running = False

        # Close the server socket to stop accept_connections
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None

        # Disconnect all clients
        for client_socket in list(self.clients.keys()):
            self.disconnect_client(client_socket)

        # Wait for accept thread to finish if it exists
        if self.accept_thread and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=1.0)

        self.log_message("Server stopped.")

        # Reset statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_messages": 0,
            "start_time": None
        }

        return True, "Server stopped successfully"

    def accept_connections(self):
        """Handle incoming client connections"""
        while self.is_running:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.is_running:  # Only show error if server is still meant to be running
                    self.log_message(f"Error accepting connection: {str(e)}")

    def handle_client(self, client_socket, client_address):
        try:
            ip, port = client_address
            self.log_message(f"Client connected: {ip}:{port}")

            # Update statistics
            self.stats["total_connections"] += 1
            self.stats["active_connections"] += 1

            # Pass client address to the key exchange function
            symmetric_key = self.perform_key_exchange(client_socket, client_address)

            self.clients[client_socket] = {
                "address": client_address,
                "symmetric_key": symmetric_key,
                "rooms": [],
                "connect_time": datetime.now()
            }

            while self.is_running:
                try:
                    encrypted_data = receive_encrypted_data(client_socket)
                    decrypted_message = AESGCMCipher.decrypt(symmetric_key, encrypted_data)
                    self.stats["total_messages"] += 1

                    if decrypted_message.startswith("/join "):
                        room_name = decrypted_message.split(" ", 1)[1].strip()
                        self.join_room(client_socket, room_name)
                    elif decrypted_message.startswith("/leave "):
                        room_name = decrypted_message.split(" ", 1)[1].strip()
                        self.leave_room(client_socket, room_name)
                    elif decrypted_message.startswith("/msg "):
                        # New message format: "/msg room_name username: message"
                        parts = decrypted_message.split(" ", 2)
                        if len(parts) >= 3:
                            room_name = parts[1]
                            message_content = parts[2]
                            self.broadcast_to_room(message_content, client_socket, room_name)
                    else:
                        # Legacy support for old message format
                        self.broadcast(decrypted_message, client_socket)

                except Exception as e:
                    self.log_message(f"Error with client {ip}:{port}: {str(e)}")
                    break

        finally:
            self.disconnect_client(client_socket)

    def broadcast_to_room(self, message, sender_socket, room_name):
        try:
            # Check if room exists and client is in it
            if room_name not in self.rooms:
                return

            if sender_socket not in self.rooms[room_name]:
                return

            sender_ip, sender_port = self.clients[sender_socket]["address"]

            # Create room-specific hash for the message
            formatted_message = f"[{room_name}] {message}"
            room_hashed_message = RoomHasher.hash_message(formatted_message, room_name)

            self.log_message(f"Message in {room_name} from {sender_ip}:{sender_port}: {message}")

            # Send to other clients in this room only
            for client_socket in self.rooms[room_name]:
                if client_socket != sender_socket:
                    try:
                        symmetric_key = self.clients[client_socket]["symmetric_key"]
                        encrypted_message = AESGCMCipher.encrypt(symmetric_key, room_hashed_message)
                        send_encrypted_data(client_socket, encrypted_message)
                    except Exception as e:
                        self.log_message(f"Error broadcasting message: {str(e)}")
        except Exception as e:
            self.log_message(f"Error in room broadcast: {str(e)}")

    def disconnect_client(self, client_socket):
        if client_socket in self.clients:
            ip, port = self.clients[client_socket]["address"]

            # Leave all rooms
            for room_name in list(self.clients[client_socket]["rooms"]):
                self.leave_room(client_socket, room_name)

            # Update statistics
            self.stats["active_connections"] -= 1

            # Clean up client data
            del self.clients[client_socket]
            client_socket.close()

            self.log_message(f"Client disconnected: {ip}:{port}")

    def join_room(self, client_socket, room_name):
        if room_name not in self.rooms:
            self.rooms[room_name] = []
            # Initialize room hash key when room is created
            RoomHasher.create_room_key(room_name)
            self.log_message(f"Created new room with unique hash key: {room_name}")

        if client_socket not in self.rooms[room_name]:
            self.rooms[room_name].append(client_socket)
            self.clients[client_socket]["rooms"].append(room_name)

            room_key_data = RoomHasher.export_room_key(room_name)
            key_message = f"/room_key {room_name} {room_key_data}"
            symmetric_key = self.clients[client_socket]["symmetric_key"]
            encrypted_message = AESGCMCipher.encrypt(symmetric_key, key_message)
            send_encrypted_data(client_socket, encrypted_message)

            ip, port = self.clients[client_socket]["address"]
            self.log_message(f"Client {ip}:{port} joined room: {room_name}")

            # Notify all clients in the room about the new member
            join_message = f"User {ip}:{port} has joined the room."
            self.broadcast_system_message(join_message, room_name)

    def leave_room(self, client_socket, room_name):
        if room_name in self.rooms and client_socket in self.rooms[room_name]:
            ip, port = self.clients[client_socket]["address"]

            self.rooms[room_name].remove(client_socket)
            self.clients[client_socket]["rooms"].remove(room_name)

            self.log_message(f"Client {ip}:{port} left room: {room_name}")

            # Notify remaining clients
            leave_message = f"User {ip}:{port} has left the room."
            self.broadcast_system_message(leave_message, room_name)

            # Clean up empty rooms
            if not self.rooms[room_name]:
                del self.rooms[room_name]
                self.log_message(f"Room '{room_name}' has been closed (no active users)")

    def broadcast_system_message(self, message, room_name):
        system_message = f"[SYSTEM] {message}"

        # Apply room-specific hashing to system messages too
        hashed_system_message = RoomHasher.hash_message(system_message, room_name)

        if room_name in self.rooms:
            for client_socket in self.rooms[room_name]:
                try:
                    symmetric_key = self.clients[client_socket]["symmetric_key"]
                    encrypted_message = AESGCMCipher.encrypt(symmetric_key, hashed_system_message)
                    send_encrypted_data(client_socket, encrypted_message)
                except Exception as e:
                    self.log_message(f"Error sending system message: {str(e)}")

    def broadcast(self, message, sender_socket):
        try:
            sender_ip, sender_port = self.clients[sender_socket]["address"]
            sender_rooms = self.clients[sender_socket]["rooms"]

            # Extract username from the message (assuming format "Username: message")
            username = message.split(":", 1)[0]
            message_content = message.split(":", 1)[1] if ":" in message else message

            for room_name in sender_rooms:
                if room_name not in self.rooms:
                    continue  # Skip if room doesn't exist anymore

                # Create a cleaner formatted message with just the username
                formatted_message = f"[{room_name}] {username}:{message_content}"
                room_hashed_message = RoomHasher.hash_message(formatted_message, room_name)

                self.log_message(f"Message in {room_name} from {sender_ip}:{sender_port}: {message}")

                # Only broadcast to clients that are actually in this room
                for client_socket in self.rooms[room_name]:
                    if client_socket != sender_socket:
                        try:
                            symmetric_key = self.clients[client_socket]["symmetric_key"]
                            encrypted_message = AESGCMCipher.encrypt(symmetric_key, room_hashed_message)
                            send_encrypted_data(client_socket, encrypted_message)
                        except Exception as e:
                            self.log_message(f"Error broadcasting message: {str(e)}")
        except Exception as e:
            self.log_message(f"Error in broadcast: {str(e)}")

    def perform_key_exchange(self, client_socket, client_address=None):
        try:
            print("Server: Starting TLS 1.3 handshake")
            client_ip = client_address[0] if client_address else ""

            # Initialize cryptographic server materials
            ssl_handler = self._initialize_server_materials()

            # Process ClientHello
            client_data = self._receive_client_hello(client_socket)
            client_public_key_bytes = client_data["public_key_bytes"]
            client_signing_public = client_data["signing_public"]
            client_timestamp = client_data["timestamp"]
            username = client_data["username"]

            # Verify client signature - now including IP
            self._verify_client_signature(
                client_public_key_bytes,
                client_data["signature"],
                client_signing_public,
                client_timestamp,
                username,
                client_ip
            )

            # Prepare and send ServerHello
            client_public_key = KeyExchange.deserialize_public_key(client_public_key_bytes)
            server_data = self._prepare_server_materials(client_timestamp)
            server_public_bytes = server_data["public_bytes"]

            # Create signatures - now including client IP
            signatures = self._create_server_signatures(
                server_public_bytes,
                client_public_key_bytes,
                client_timestamp,
                server_data["signing_private"],
                ssl_handler,
                client_ip
            )

            # Send ServerHello
            self._send_server_hello(
                client_socket,
                ssl_handler,
                server_public_bytes,
                server_data["signing_public_bytes"],
                signatures
            )

            # Derive symmetric key
            symmetric_key = self._derive_symmetric_key(server_data["private_key"], client_public_key)

            return symmetric_key

        except Exception as e:
            print(f"Server: Key exchange failed: {str(e)}")
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def _initialize_server_materials(self):
        """Initialize SSL handler and generate key pairs."""
        ssl_handler = OpenSSLCertHandler("E:/swords and sandals/OpenSSL/keys/server.crt",
                                         "E:/swords and sandals/OpenSSL/keys/server.key")
        self.private_key, self.public_key = KeyExchange.generate_key_pair()
        self.signing_private, self.signing_public = DigitalSignature.generate_keypair()
        print("Server: Generated keypairs")
        return ssl_handler

    def _receive_client_hello(self, client_socket):
        """Receive and parse the ClientHello message."""
        # Receive client's public key
        public_key_len = int.from_bytes(client_socket.recv(4), 'big')
        client_public_key_bytes = client_socket.recv(public_key_len)

        # Receive client's signing public key
        signing_key_len = int.from_bytes(client_socket.recv(4), 'big')
        client_signing_public_bytes = client_socket.recv(signing_key_len)

        # Receive timestamp from ClientHello
        client_timestamp = int.from_bytes(client_socket.recv(8), 'big')

        # Receive client's signature
        signature_len = int.from_bytes(client_socket.recv(4), 'big')
        client_signature = client_socket.recv(signature_len)

        # Receive username
        username_len = int.from_bytes(client_socket.recv(4), 'big')
        username = client_socket.recv(username_len).decode('utf-8')

        print("Server: Received ClientHello with key share")

        # Parse client's signing public key
        client_signing_public = DigitalSignature.deserialize_public_key(client_signing_public_bytes)

        return {
            "public_key_bytes": client_public_key_bytes,
            "signing_public": client_signing_public,
            "timestamp": client_timestamp,
            "signature": client_signature,
            "username": username
        }

    def _verify_client_signature(self, client_public_key_bytes, client_signature,
                                 client_signing_public, client_timestamp, username, client_ip=""):
        """Verify the client's signature."""
        # First try with the provided IP
        if DigitalSignature.verify_message(
                client_public_key_bytes.hex(),
                client_signature,
                client_signing_public,
                client_ip,
                client_timestamp,
                username
        ):
            print(f"Server: Verified client signature with IP: {client_ip}")
            return True

        # Next try with localhost/127.0.0.1 if the client IP seems to be a local IP
        if client_ip in ["127.0.0.1", "localhost"] or client_ip.startswith("192.168.") or client_ip.startswith("10."):
            for test_ip in ["127.0.0.1", "localhost", "", "0.0.0.0"]:
                if DigitalSignature.verify_message(
                        client_public_key_bytes.hex(),
                        client_signature,
                        client_signing_public,
                        test_ip,
                        client_timestamp,
                        username
                ):
                    print(f"Server: Verified client signature with alternative local IP: {test_ip}")
                    return True

        # Finally, try with empty IP as a last resort
        if DigitalSignature.verify_message(
                client_public_key_bytes.hex(),
                client_signature,
                client_signing_public,
                "",
                client_timestamp,
                username
        ):
            print("Server: Verified client signature with empty IP")
            return True

        raise ConnectionError("Invalid client signature")

    def _prepare_server_materials(self, client_timestamp):
        """Prepare the server's key material for ServerHello."""
        # Generate server's key share
        server_public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        server_signing_public_bytes = self.signing_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "private_key": self.private_key,
            "public_bytes": server_public_bytes,
            "signing_private": self.signing_private,
            "signing_public_bytes": server_signing_public_bytes,
            "timestamp": client_timestamp
        }

    def _create_server_signatures(self, server_public_bytes, client_public_key_bytes,
                                  timestamp, signing_private, ssl_handler, client_ip=""):
        """Create the signatures for the ServerHello message."""
        # Create server signature with client IP
        server_signature = DigitalSignature.sign_message(
            server_public_bytes.hex(),
            signing_private,
            client_ip,  # Now including client IP
            timestamp,
            "server"
        )

        # Generate OpenSSL signature
        data_to_sign = client_public_key_bytes + server_public_bytes
        openssl_signature = ssl_handler.sign_data(data_to_sign)

        return {
            "server_signature": server_signature,
            "openssl_signature": openssl_signature
        }

    def _send_server_hello(self, client_socket, ssl_handler, server_public_bytes,
                           server_signing_public_bytes, signatures):
        """Send the ServerHello message to the client."""
        # Send certificate
        cert_data = ssl_handler.get_certificate_data()
        client_socket.send(len(cert_data).to_bytes(4, 'big'))
        client_socket.send(cert_data)

        # Send server public key
        client_socket.send(len(server_public_bytes).to_bytes(4, 'big'))
        client_socket.send(server_public_bytes)

        # Send server signing public key
        client_socket.send(len(server_signing_public_bytes).to_bytes(4, 'big'))
        client_socket.send(server_signing_public_bytes)

        # Send server signature
        server_signature = signatures["server_signature"]
        client_socket.send(len(server_signature).to_bytes(4, 'big'))
        client_socket.send(server_signature)

        # Send OpenSSL signature
        openssl_signature = signatures["openssl_signature"]
        client_socket.send(len(openssl_signature).to_bytes(4, 'big'))
        client_socket.send(openssl_signature)

        print("Server: Sent ServerHello with key share")

    def _derive_symmetric_key(self, private_key, client_public_key):
        """Derive the shared symmetric key."""
        shared_secret = KeyExchange.generate_shared_secret(private_key, client_public_key)
        symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
        print("Server: TLS 1.3 handshake completed successfully")
        return symmetric_key

    def get_stats(self):
        """Return a dictionary of server statistics"""
        uptime = None
        if self.stats["start_time"]:
            uptime = datetime.now() - self.stats["start_time"]

        return {
            "total_connections": self.stats["total_connections"],
            "active_connections": self.stats["active_connections"],
            "total_messages": self.stats["total_messages"],
            "active_rooms": len(self.rooms),
            "uptime": uptime,
            "host": self.host,
            "port": self.port,
            "running": self.is_running
        }

    def get_client_list(self):
        """Return a list of dictionaries containing client information"""
        client_list = []
        for client_socket, client_data in self.clients.items():
            ip, port = client_data["address"]
            connected_time = datetime.now() - client_data.get("connect_time", datetime.now())
            rooms = client_data["rooms"]

            client_list.append({
                "ip": ip,
                "port": port,
                "connected_time": str(connected_time).split(".")[0],
                "rooms": rooms
            })

        return client_list

    def get_room_list(self):
        """Return a list of dictionaries containing room information"""
        room_list = []
        for room_name, clients in self.rooms.items():
            room_list.append({
                "name": room_name,
                "active_users": len(clients),
                "message_count": "N/A"  # Could be enhanced to track messages per room
            })

        return room_list

    def disconnect_client_by_address(self, ip, port):
        """Disconnect a client by its IP address and port"""
        for client_socket, client_data in list(self.clients.items()):
            if client_data["address"] == (ip, int(port)):
                self.disconnect_client(client_socket)
                return True
        return False

    def close_room(self, room_name):
        """Close a room and notify all clients before removing it"""
        if room_name in self.rooms:
            # First notify all clients in the room that it's being closed
            close_message = f"Room '{room_name}' is being closed by the server."
            self.broadcast_system_message(close_message, room_name)

            # Send a special command to tell clients to remove the room
            remove_command = f"/room_closed {room_name}"
            for client_socket in self.rooms[room_name][:]:
                try:
                    symmetric_key = self.clients[client_socket]["symmetric_key"]
                    encrypted_command = AESGCMCipher.encrypt(symmetric_key, remove_command)
                    send_encrypted_data(client_socket, encrypted_command)

                    # Remove the room from the client's list of rooms
                    if room_name in self.clients[client_socket]["rooms"]:
                        self.clients[client_socket]["rooms"].remove(room_name)
                except Exception as e:
                    self.log_message(f"Error notifying client about room closure: {str(e)}")

            # Clear the room
            self.rooms.pop(room_name)
            self.log_message(f"Room '{room_name}' has been closed by admin")
            return True
        return False