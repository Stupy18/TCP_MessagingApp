import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import base64
from cryptography.hazmat.primitives import serialization

from TLS.DigitalSigniture import DigitalSignature
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.AES_CBC_CYPHER import AESCBCCipher, send_encrypted_data, receive_encrypted_data
import json
from datetime import datetime

from TLS.OpenSSlCertHandler import OpenSSLCertHandler
from TLS.RSAKeyExchange import RSAKeyExchange


class ModernServerGUI:
    def __init__(self):
        self.host = None
        self.port = 8080
        self.server_socket = None
        self.clients = {}
        self.rooms = {}
        self.is_running = False
        self.ecdsa_private_key, self.ecdsa_public_key = DigitalSignature.generate_keypair()

        print("Server: Generating RSA key pair during initialization")
        self.rsa_private_key, self.rsa_public_key = RSAKeyExchange.generate_key_pair()

        # Main window setup
        self.root = tk.Tk()
        self.root.title("Secure Chat Server Dashboard")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Configure style
        self.setup_styles()

        # Create main container
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.pack(expand=True, fill=tk.BOTH)

        # Create layout
        self.create_header_frame()
        self.create_main_content()
        self.create_status_bar()

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Initialize statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_messages": 0,
            "start_time": None
        }

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Define colors
        self.colors = {
            "primary": "#1a237e",  # Deep blue
            "secondary": "#283593",
            "accent": "#3949ab",
            "success": "#43a047",
            "warning": "#fdd835",
            "danger": "#e53935",
            "text": "#ffffff",
            "text_dark": "#212121",
            "background": "#f5f5f5"
        }

        # Configure styles
        self.style.configure("Header.TFrame", background=self.colors["primary"])
        self.style.configure("Main.TFrame", background=self.colors["background"])
        self.style.configure("Status.TFrame", background=self.colors["primary"])

        self.style.configure("Header.TLabel",
                             background=self.colors["primary"],
                             foreground=self.colors["text"],
                             font=("Helvetica", 12, "bold"))

        self.style.configure("Status.TLabel",
                             background=self.colors["primary"],
                             foreground=self.colors["text"],
                             font=("Helvetica", 9))

        # Button styles
        self.style.configure("Control.TButton",
                             font=("Helvetica", 10),
                             padding=5)

        self.style.configure("Action.TButton",
                             font=("Helvetica", 10),
                             padding=5)

        self.style.configure("Danger.TButton",
                             font=("Helvetica", 10),
                             padding=5)

        self.style.map("Control.TButton",
                       background=[("active", self.colors["accent"]),
                                   ("disabled", self.colors["secondary"])],
                       foreground=[("active", self.colors["text"]),
                                   ("disabled", self.colors["text"])])

        self.style.map("Action.TButton",
                       background=[("active", self.colors["success"]),
                                   ("disabled", self.colors["secondary"])],
                       foreground=[("active", self.colors["text"]),
                                   ("disabled", self.colors["text"])])

        self.style.map("Danger.TButton",
                       background=[("active", self.colors["danger"]),
                                   ("disabled", self.colors["secondary"])],
                       foreground=[("active", self.colors["text"]),
                                   ("disabled", self.colors["text"])])

    def create_header_frame(self):
        header_frame = ttk.Frame(self.main_container, style="Header.TFrame")
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Server controls
        controls_frame = ttk.Frame(header_frame, style="Header.TFrame")
        controls_frame.pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_frame, text="Server IP:", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        self.host_entry = ttk.Entry(controls_frame, width=15)
        self.host_entry.insert(0, "0.0.0.0")
        self.host_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_frame, text="Port:", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        self.port_entry = ttk.Entry(controls_frame, width=6)
        self.port_entry.insert(0, str(self.port))
        self.port_entry.pack(side=tk.LEFT, padx=5)

        self.start_button = ttk.Button(controls_frame, text="Start Server",
                                       command=self.start, style="Control.TButton")
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(controls_frame, text="Stop Server",
                                      command=self.stop, style="Danger.TButton", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Server status
        status_frame = ttk.Frame(header_frame, style="Header.TFrame")
        status_frame.pack(side=tk.RIGHT, padx=5)

        self.status_label = ttk.Label(status_frame, text="Server Status: Stopped",
                                      style="Header.TLabel")
        self.status_label.pack(side=tk.RIGHT, padx=5)

    def create_main_content(self):
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(expand=True, fill=tk.BOTH, pady=5)

        # Server Log Tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Server Log")

        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(log_controls, text="Export Logs",
                   command=self.export_logs, style="Action.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="Clear Logs",
                   command=self.clear_logs, style="Danger.TButton").pack(side=tk.LEFT, padx=5)

        self.text_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD,
                                                     height=15, font=("Consolas", 10))
        self.text_widget.pack(expand=True, fill=tk.BOTH, pady=5)

        # Clients Tab
        clients_frame = ttk.Frame(self.notebook)
        self.notebook.add(clients_frame, text="Connected Clients")

        # Client controls
        client_controls = ttk.Frame(clients_frame)
        client_controls.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(client_controls, text="Disconnect Selected",
                   command=self.disconnect_selected_client,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(client_controls, text="Disconnect All",
                   command=self.disconnect_all_clients,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(client_controls, text="Refresh List",
                   command=self.update_client_list,
                   style="Action.TButton").pack(side=tk.LEFT, padx=5)

        # Create treeview for clients
        columns = ("IP", "Port", "Connected Time", "Active Rooms")
        self.clients_tree = ttk.Treeview(clients_frame, columns=columns, show="headings")

        # Configure columns
        for col in columns:
            self.clients_tree.heading(col, text=col)
            self.clients_tree.column(col, width=150)

        self.clients_tree.pack(expand=True, fill=tk.BOTH, pady=5)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(clients_frame, orient=tk.VERTICAL,
                                  command=self.clients_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.clients_tree.configure(yscrollcommand=scrollbar.set)

        # Rooms Tab
        rooms_frame = ttk.Frame(self.notebook)
        self.notebook.add(rooms_frame, text="Chat Rooms")

        # Room controls
        room_controls = ttk.Frame(rooms_frame)
        room_controls.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(room_controls, text="Close Selected Room",
                   command=self.close_selected_room,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(room_controls, text="Close All Rooms",
                   command=self.close_all_rooms,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(room_controls, text="Refresh Rooms",
                   command=self.update_rooms_list,
                   style="Action.TButton").pack(side=tk.LEFT, padx=5)

        # Create treeview for rooms
        room_columns = ("Room Name", "Active Users", "Messages")
        self.rooms_tree = ttk.Treeview(rooms_frame, columns=room_columns, show="headings")

        for col in room_columns:
            self.rooms_tree.heading(col, text=col)
            self.rooms_tree.column(col, width=150)

        self.rooms_tree.pack(expand=True, fill=tk.BOTH, pady=5)

    def clear_logs(self):
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear the logs?"):
            self.text_widget.configure(state=tk.NORMAL)
            self.text_widget.delete(1.0, tk.END)
            self.text_widget.configure(state=tk.DISABLED)

    def disconnect_selected_client(self):
        selection = self.clients_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a client to disconnect")
            return

        if messagebox.askyesno("Confirm Disconnect", "Are you sure you want to disconnect the selected client?"):
            for item in selection:
                values = self.clients_tree.item(item)['values']
                ip, port = values[0], values[1]

                # Find the corresponding client socket
                for client_socket, client_data in self.clients.items():
                    if client_data["address"] == (ip, int(port)):
                        self.disconnect_client(client_socket)
                        break

    def disconnect_all_clients(self):
        if not self.clients:
            messagebox.showinfo("Info", "No clients connected")
            return

        if messagebox.askyesno("Confirm Disconnect All", "Are you sure you want to disconnect all clients?"):
            for client_socket in list(self.clients.keys()):
                self.disconnect_client(client_socket)

    def close_selected_room(self):
        selection = self.rooms_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a room to close")
            return

        if messagebox.askyesno("Confirm Close Room", "Are you sure you want to close the selected room?"):
            for item in selection:
                values = self.rooms_tree.item(item)['values']
                room_name = values[0]

                if room_name in self.rooms:
                    # Disconnect all clients from the room
                    for client_socket in self.rooms[room_name][:]:
                        self.leave_room(client_socket, room_name)

    def close_all_rooms(self):
        if not self.rooms:
            messagebox.showinfo("Info", "No active rooms")
            return

        if messagebox.askyesno("Confirm Close All", "Are you sure you want to close all rooms?"):
            room_names = list(self.rooms.keys())
            for room_name in room_names:
                for client_socket in self.rooms[room_name][:]:
                    self.leave_room(client_socket, room_name)

    def create_status_bar(self):
        status_bar = ttk.Frame(self.main_container, style="Status.TFrame")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.connection_count = ttk.Label(status_bar,
                                          text="Connections: 0", style="Status.TLabel")
        self.connection_count.pack(side=tk.LEFT, padx=5)

        self.message_count = ttk.Label(status_bar,
                                       text="Messages: 0", style="Status.TLabel")
        self.message_count.pack(side=tk.LEFT, padx=5)

        self.uptime_label = ttk.Label(status_bar,
                                      text="Uptime: 0:00:00", style="Status.TLabel")
        self.uptime_label.pack(side=tk.RIGHT, padx=5)

    def update_status_bar(self):
        if self.is_running:
            self.connection_count.config(
                text=f"Active Connections: {self.stats['active_connections']}")
            self.message_count.config(
                text=f"Total Messages: {self.stats['total_messages']}")

            if self.stats["start_time"]:
                uptime = datetime.now() - self.stats["start_time"]
                hours = uptime.seconds // 3600
                minutes = (uptime.seconds % 3600) // 60
                seconds = uptime.seconds % 60
                self.uptime_label.config(
                    text=f"Uptime: {hours}:{minutes:02d}:{seconds:02d}")

            self.root.after(1000, self.update_status_bar)

    def start(self):
        try:
            self.host = self.host_entry.get()
            self.port = int(self.port_entry.get())

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(500)

            self.is_running = True
            self.stats["start_time"] = datetime.now()

            self.update_text_widget(f"Server started at {self.host}:{self.port}\n")
            self.status_label.config(text="Server Status: Running")

            # Create a separate thread for accepting connections
            self.accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            self.accept_thread.start()

            self.update_status_bar()

            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
            self.update_text_widget(f"Failed to start server: {str(e)}\n")

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
                    self.update_text_widget(f"Error accepting connection: {str(e)}\n")

    def stop(self):
        if messagebox.askyesno("Confirm Stop", "Are you sure you want to stop the server?"):
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

            self.update_text_widget("Server stopped.\n")
            self.status_label.config(text="Server Status: Stopped")

            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.host_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)

            # Reset statistics
            self.stats = {
                "total_connections": 0,
                "active_connections": 0,
                "total_messages": 0,
                "start_time": None
            }

    def update_text_widget(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"

        self.text_widget.configure(state=tk.NORMAL)
        self.text_widget.insert(tk.END, formatted_message)
        self.text_widget.configure(state=tk.DISABLED)
        self.text_widget.see(tk.END)

    def update_client_list(self):
        # Clear existing items
        for item in self.clients_tree.get_children():
            self.clients_tree.delete(item)

        # Add current clients
        for client_socket, client_data in self.clients.items():
            ip, port = client_data["address"]
            connected_time = datetime.now() - client_data.get("connect_time", datetime.now())
            rooms = ", ".join(client_data["rooms"]) or "None"

            self.clients_tree.insert("", tk.END, values=(
                ip,
                port,
                str(connected_time).split(".")[0],
                rooms
            ))

    def update_rooms_list(self):
        # Clear existing items
        for item in self.rooms_tree.get_children():
            self.rooms_tree.delete(item)

        # Add current rooms
        for room_name, clients in self.rooms.items():
            self.rooms_tree.insert("", tk.END, values=(
                room_name,
                len(clients),
                self.get_room_message_count(room_name)
            ))

    def get_room_message_count(self, room_name):
        # This could be enhanced to actually track messages per room
        return "N/A"

    def handle_client(self, client_socket, client_address):
        try:
            ip, port = client_address
            self.update_text_widget(f"Client connected: {ip}:{port}\n")

            # Update statistics
            self.stats["total_connections"] += 1
            self.stats["active_connections"] += 1

            symmetric_key = self.perform_key_exchange(client_socket)

            self.clients[client_socket] = {
                "address": client_address,
                "symmetric_key": symmetric_key,
                "rooms": [],
                "connect_time": datetime.now()
            }

            self.root.after(0, self.update_client_list)

            while self.is_running:
                try:
                    encrypted_data = receive_encrypted_data(client_socket)

                    decrypted_message = AESCBCCipher.decrypt(symmetric_key, encrypted_data)

                    self.stats["total_messages"] += 1

                    if decrypted_message.startswith("/join "):
                        room_name = decrypted_message.split(" ", 1)[1].strip()
                        self.join_room(client_socket, room_name)
                    elif decrypted_message.startswith("/leave "):
                        room_name = decrypted_message.split(" ", 1)[1].strip()
                        self.leave_room(client_socket, room_name)
                    else:
                        self.broadcast(decrypted_message, client_socket)

                    self.root.after(0, self.update_rooms_list)

                except Exception as e:
                    self.update_text_widget(f"Error with client {ip}:{port}: {str(e)}\n")

                    break

        finally:
            self.disconnect_client(client_socket)

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

            self.update_text_widget(f"Client disconnected: {ip}:{port}\n")
            self.root.after(0, lambda: (self.update_client_list(), self.update_rooms_list()))

    def join_room(self, client_socket, room_name):
        if room_name not in self.rooms:
            self.rooms[room_name] = []

        if client_socket not in self.rooms[room_name]:
            self.rooms[room_name].append(client_socket)
            self.clients[client_socket]["rooms"].append(room_name)

            ip, port = self.clients[client_socket]["address"]
            self.update_text_widget(f"Client {ip}:{port} joined room: {room_name}\n")

            # Notify all clients in the room about the new member
            join_message = f"User {ip}:{port} has joined the room."
            self.broadcast_system_message(join_message, room_name)

            self.root.after(0, lambda: (self.update_client_list(), self.update_rooms_list()))

    def leave_room(self, client_socket, room_name):
        if room_name in self.rooms and client_socket in self.rooms[room_name]:
            ip, port = self.clients[client_socket]["address"]

            self.rooms[room_name].remove(client_socket)
            self.clients[client_socket]["rooms"].remove(room_name)

            self.update_text_widget(f"Client {ip}:{port} left room: {room_name}\n")

            # Notify remaining clients
            leave_message = f"User {ip}:{port} has left the room."
            self.broadcast_system_message(leave_message, room_name)

            # Clean up empty rooms
            if not self.rooms[room_name]:
                del self.rooms[room_name]
                self.update_text_widget(f"Room '{room_name}' has been closed (no active users)\n")

            self.root.after(0, lambda: (self.update_client_list(), self.update_rooms_list()))

    def broadcast_system_message(self, message, room_name):
        system_message = f"[SYSTEM] {message}"
        if room_name in self.rooms:
            for client_socket in self.rooms[room_name]:
                try:
                    symmetric_key = self.clients[client_socket]["symmetric_key"]
                    encrypted_message = AESCBCCipher.encrypt(symmetric_key, system_message)
                    send_encrypted_data(client_socket, encrypted_message)
                except Exception as e:
                    self.update_text_widget(f"Error sending system message: {str(e)}\n")

    def broadcast(self, message, sender_socket):
        try:
            sender_ip, sender_port = self.clients[sender_socket]["address"]
            sender_rooms = self.clients[sender_socket]["rooms"]

            for room_name in sender_rooms:
                if room_name not in self.rooms:
                    continue  # Skip if room doesn't exist anymore

                formatted_message = f"[{room_name}] {sender_ip}:{sender_port}: {message}"
                self.update_text_widget(formatted_message + "\n")

                # Only broadcast to clients that are actually in this room
                for client_socket in self.rooms[room_name]:
                    if client_socket != sender_socket:
                        try:
                            symmetric_key = self.clients[client_socket]["symmetric_key"]
                            encrypted_message = AESCBCCipher.encrypt(symmetric_key, formatted_message)
                            send_encrypted_data(client_socket, encrypted_message)
                        except Exception as e:

                            self.update_text_widget(f"Error broadcasting message: {str(e)}\n")
        except Exception as e:

            self.update_text_widget(f"Error in broadcast: {str(e)}\n")

    def perform_key_exchange(self, client_socket):
        try:
            print("Server: Starting TLS 1.2 handshake")

            # Step 1: Initialize cryptographic server materials
            print("Server: Initializing server materials")
            ssl_handler = self._initialize_server_materials()
            # Get the certificate's private key
            cert_private_key = ssl_handler.get_private_key()

            # Step 2: Process ClientHello
            print("Server: Waiting for ClientHello")
            client_data = self._receive_client_hello(client_socket)
            client_signing_public = client_data["signing_public"]
            client_timestamp = client_data["timestamp"]
            username = client_data["username"]
            print(f"Server: Received ClientHello from {username}")

            # Verify client signature
            print("Server: Verifying client signature")
            self._verify_client_signature(
                client_data["signature"],
                client_signing_public,
                client_timestamp,
                username
            )
            print("Server: Client signature verified")

            # Step 3: Send ServerHello with certificate and signature
            print("Server: Preparing server materials")
            server_data = self._prepare_server_materials(client_timestamp)

            # Create signature
            print("Server: Creating server signature")
            signature = self._create_server_signature(
                client_timestamp,
                server_data["signing_private"],
            )

            # Send ServerHello
            print("Server: Sending ServerHello")
            self._send_server_hello(
                client_socket,
                ssl_handler,
                server_data["signing_public_bytes"],
                signature
            )

            # Step 4: Receive encrypted pre-master secret from client
            print("Server: Waiting for encrypted pre-master secret")
            encrypted_pre_master_secret = self._receive_encrypted_pre_master_secret(client_socket)
            print(f"Server: Received encrypted pre-master secret ({len(encrypted_pre_master_secret)} bytes)")

            # Decrypt pre-master secret and derive symmetric key
            print("Server: Decrypting pre-master secret")
            pre_master_secret = RSAKeyExchange.decrypt_pre_master_secret(
                cert_private_key,  # Use the certificate's private key
                encrypted_pre_master_secret
            )

            # Derive symmetric key
            print("Server: Deriving symmetric key")
            symmetric_key = KeyDerivation.derive_symmetric_key(pre_master_secret)

            print("Server: TLS 1.2 handshake completed successfully")
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
        print("Server: Waiting for client public key length")
        # Receive client's signing public key
        signing_key_len = int.from_bytes(client_socket.recv(4), 'big')
        print(f"Server: Receiving client signing key ({signing_key_len} bytes)")
        client_signing_public_bytes = client_socket.recv(signing_key_len)

        # Receive timestamp from ClientHello
        print("Server: Receiving timestamp")
        client_timestamp = int.from_bytes(client_socket.recv(8), 'big')

        # Receive client's signature
        print("Server: Waiting for client signature length")
        signature_len = int.from_bytes(client_socket.recv(4), 'big')
        print(f"Server: Receiving client signature ({signature_len} bytes)")
        client_signature = client_socket.recv(signature_len)

        # Receive username
        print("Server: Waiting for username length")
        username_len = int.from_bytes(client_socket.recv(4), 'big')
        print(f"Server: Receiving username ({username_len} bytes)")
        username = client_socket.recv(username_len).decode('utf-8')

        print(f"Server: Received ClientHello from {username}")

        # Parse client's signing public key
        print("Server: Deserializing client signing key")
        client_signing_public = DigitalSignature.deserialize_public_key(client_signing_public_bytes)

        return {
            "signing_public": client_signing_public,
            "timestamp": client_timestamp,
            "signature": client_signature,
            "username": username
        }

    def _verify_client_signature(self, client_signature, client_signing_public, client_timestamp, username):
        """Verify the client's signature."""
        if not DigitalSignature.verify_message(
                "",  # Empty message since we're not verifying public key bytes anymore
                client_signature,
                client_signing_public,
                "",
                client_timestamp,
                username
        ):
            raise ConnectionError("Invalid client signature")

        print("Server: Verified client signature")

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
                                  timestamp, signing_private, ssl_handler):
        """Create the signatures for the ServerHello message."""
        # Create server signature
        server_signature = DigitalSignature.sign_message(
            server_public_bytes.hex(),
            signing_private,
            "",
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

    def _send_server_hello(self, client_socket, ssl_handler, server_signing_public_bytes, signature):
        """Send the ServerHello message to the client."""
        # Send certificate
        print("Server: Getting certificate data")
        cert_data = ssl_handler.get_certificate_data()
        print(f"Server: Sending certificate ({len(cert_data)} bytes)")
        client_socket.send(len(cert_data).to_bytes(4, 'big'))
        client_socket.send(cert_data)

        # Send server signing public key
        print(f"Server: Sending server signing key ({len(server_signing_public_bytes)} bytes)")
        client_socket.send(len(server_signing_public_bytes).to_bytes(4, 'big'))
        client_socket.send(server_signing_public_bytes)

        # Send server signature
        print(f"Server: Sending server signature ({len(signature)} bytes)")
        client_socket.send(len(signature).to_bytes(4, 'big'))
        client_socket.send(signature)

        print("Server: ServerHello sent successfully")

    def _receive_encrypted_pre_master_secret(self, client_socket):
        """Receive the encrypted pre-master secret from the client."""
        print("Server: Waiting for pre-master secret length")
        secret_len = int.from_bytes(client_socket.recv(4), 'big')
        print(f"Server: Receiving encrypted pre-master secret ({secret_len} bytes)")
        encrypted_secret = client_socket.recv(secret_len)
        return encrypted_secret

    def _derive_symmetric_key(self, private_key, client_public_key):
        """Derive the shared symmetric key."""
        shared_secret = KeyExchange.generate_shared_secret(private_key, client_public_key)
        symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
        print("Server: TLS 1.3 handshake completed successfully")
        return symmetric_key

    def on_closing(self):
        if self.is_running:
            if messagebox.askyesno("Quit", "Server is running. Stop server and quit?"):
                self.stop()
                self.root.destroy()
        else:
            self.root.destroy()

    def export_logs(self):
        """Export server logs to a file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"server_log_{timestamp}.txt"

            with open(filename, "w") as f:
                f.write(self.text_widget.get("1.0", tk.END))

            messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {str(e)}")

    def show_server_info(self):
        """Display server information and statistics"""
        info = f"""
    Server Information:
    ------------------
    Host: {self.host or 'Not running'}
    Port: {self.port}
    Status: {'Running' if self.is_running else 'Stopped'}

    Statistics:
    -----------
    Total Connections: {self.stats['total_connections']}
    Active Connections: {self.stats['active_connections']}
    Total Messages: {self.stats['total_messages']}
    Active Rooms: {len(self.rooms)}
    """
        messagebox.showinfo("Server Information", info)

    def run(self):
        # Add menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_command(label="Clear Logs", command=self.clear_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        # Server menu
        server_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Server", menu=server_menu)
        server_menu.add_command(label="Start Server", command=self.start)
        server_menu.add_command(label="Stop Server", command=self.stop)
        server_menu.add_separator()
        server_menu.add_command(label="Server Information", command=self.show_server_info)

        # Clients menu
        clients_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Clients", menu=clients_menu)
        clients_menu.add_command(label="Disconnect Selected", command=self.disconnect_selected_client)
        clients_menu.add_command(label="Disconnect All", command=self.disconnect_all_clients)
        clients_menu.add_separator()
        clients_menu.add_command(label="Refresh Client List", command=self.update_client_list)

        # Rooms menu
        rooms_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Rooms", menu=rooms_menu)
        rooms_menu.add_command(label="Close Selected Room", command=self.close_selected_room)
        rooms_menu.add_command(label="Close All Rooms", command=self.close_all_rooms)
        rooms_menu.add_separator()
        rooms_menu.add_command(label="Refresh Room List", command=self.update_rooms_list)

        # Start the main event loop
        self.root.mainloop()

    def _receive_encrypted_pre_master_secret(self, client_socket):
        """Receive the encrypted pre-master secret from the client."""
        secret_len = int.from_bytes(client_socket.recv(4), 'big')
        encrypted_secret = client_socket.recv(secret_len)
        return encrypted_secret

    def _create_server_signature(self, timestamp, signing_private):
        """Create the signature for the ServerHello message."""
        return DigitalSignature.sign_message(
            "",  # Empty message for TLS 1.2
            signing_private,
            "",
            timestamp,
            "server"
        )



if __name__ == "__main__":
    server_gui = ModernServerGUI()
    server_gui.run()