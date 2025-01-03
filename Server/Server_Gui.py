import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import base64
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from TLS.AES_GCM_CYPHER import AESGCMCipher
from TLS.DigitalSigniture import DigitalSignature
from TLS.KeyDerivation import KeyDerivation
from TLS.KeyExchange import KeyExchange
from TLS.OpenSSlCertHandler import OpenSSLCertHandler
from datetime import datetime

from TLS.SecurityConstants import SecurityConstants


class ModernServerGUI:
    def __init__(self):
        self.host = None
        self.port = 8080
        self.server_socket = None
        self.clients = {}
        self.rooms = {}
        self.is_running = False
        self.ecdsa_private_key, self.ecdsa_public_key = DigitalSignature.generate_keypair()

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
            "primary": "#1a237e",
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
        self.host_entry.insert(0, "127.0.0.1")
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
            self.server_socket.listen(5)

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
                if self.is_running:
                    self.update_text_widget(f"Error accepting connection: {str(e)}\n")

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
                    encrypted_data = client_socket.recv(1024)
                    if not encrypted_data:
                        break

                    try:
                        decoded_data = base64.b64decode(encrypted_data)
                        decrypted_message = AESGCMCipher.decrypt(symmetric_key, decoded_data)

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

                    except ValueError as e:
                        self.update_text_widget(f"Failed to decrypt message from {ip}:{port}: {str(e)}\n")
                        continue  # Skip this message and continue listening
                    except Exception as e:
                        self.update_text_widget(f"Error processing message from {ip}:{port}: {str(e)}\n")
                        continue

                except Exception as e:
                    self.update_text_widget(f"Error with client {ip}:{port}: {str(e)}\n")
                    break

        finally:
            self.disconnect_client(client_socket)

    def perform_key_exchange(self, client_socket):
        try:
            print("\n=== SERVER KEY EXCHANGE START ===")
            print("Loading certificates and initializing...")

            # Load OpenSSL certificate handler
            ssl_handler = OpenSSLCertHandler(
                "E:/swords and sandals/OpenSSL/keys/server.crt",
                "E:/swords and sandals/OpenSSL/keys/server.key"
            )
            print("✓ SSL handler loaded successfully")

            # First receive the X25519 public key (exactly 32 bytes)
            client_public_key_bytes = client_socket.recv(32)
            print(f"\n1. Received client's X25519 public key:")
            print(f"   Length: {len(client_public_key_bytes)} bytes")
            print(f"   Hex value: {client_public_key_bytes.hex()[:32]}...")

            # Now receive the additional client data blocks
            print("\n2. Receiving client data blocks:")
            client_blocks = [client_public_key_bytes]
            for i in range(3):  # timestamp, username, device_id
                block = client_socket.recv(SecurityConstants.BLOCK_SIZE)
                print(f"   Block {i + 1} received, length: {len(block)} bytes")
                print(f"   Content preview: {block[:32].hex()}")
                client_blocks.append(block)

            print("\n3. Extracting and preparing keys:")
            # Extract client's public key
            client_public_key = KeyExchange.deserialize_public_key(client_public_key_bytes)
            print("   ✓ Client public key deserialized")

            # Generate server's ECDHE keypair
            private_key, public_key = KeyExchange.generate_key_pair()
            server_public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            print(f"   ✓ Generated server X25519 key pair, public key length: {len(server_public_bytes)}")

            # Get server's ECDSA public key bytes
            server_ecdsa_public_bytes = self.ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print(f"   ✓ Prepared ECDSA public key, length: {len(server_ecdsa_public_bytes)}")

            print("\n4. Preparing server data blocks:")
            # Prepare server blocks
            server_blocks = [
                server_public_bytes,
                server_ecdsa_public_bytes,
                DigitalSignature.prepare_data_block(str(int(time.time()))),
                DigitalSignature.prepare_data_block(self.host)
            ]

            print("   Block structure:")
            for i, block in enumerate(server_blocks):
                print(f"   Block {i + 1}: Length = {len(block)} bytes")
                print(f"   Content preview: {block[:32].hex()}")

            print("\n5. Creating verification chain:")
            # Create verification blocks
            verify_blocks = client_blocks + server_blocks
            print(f"   Total blocks in chain: {len(verify_blocks)}")

            chain_data = b''.join(verify_blocks)
            print(f"   Total chain length: {len(chain_data)} bytes")

            # Calculate chain hash
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(chain_data)
            chain_hash = hasher.finalize()
            print(f"   Chain hash (SHA256): {chain_hash.hex()}")

            print("\n6. Generating signatures:")
            # Generate ECDSA signature
            ecdsa_signature = self.ecdsa_private_key.sign(
                chain_data,
                ec.ECDSA(hashes.SHA256())
            )
            print(f"   ECDSA signature length: {len(ecdsa_signature)} bytes")
            print(f"   Signature preview: {ecdsa_signature[:32].hex()}")

            # Sign with OpenSSL
            openssl_signature = ssl_handler.sign_data(chain_data)
            print(f"   OpenSSL signature length: {len(openssl_signature)} bytes")
            print(f"   Signature preview: {openssl_signature[:32].hex()}")

            print("\n7. Sending data to client:")
            # Send certificate
            cert_data = ssl_handler.get_certificate_data()
            cert_len_bytes = len(cert_data).to_bytes(4, 'big', signed=False)
            print(f"   Certificate length bytes: {cert_len_bytes.hex()}")
            print(f"   Certificate actual length: {len(cert_data)}")
            client_socket.send(cert_len_bytes)

            # Send certificate in blocks
            remaining = len(cert_data)
            sent = 0
            while remaining > 0:
                chunk_size = min(SecurityConstants.BLOCK_SIZE, remaining)
                chunk = cert_data[sent:sent + chunk_size]
                client_socket.send(chunk)
                sent += chunk_size
                remaining -= chunk_size
                print(f"   Sent certificate chunk: {chunk_size} bytes")
            print(f"   ✓ Sent complete certificate ({len(cert_data)} bytes)")

            # Send server's X25519 public key
            client_socket.send(server_public_bytes)
            print("   ✓ Sent server X25519 public key")

            # Send ECDSA public key
            client_socket.send(len(server_ecdsa_public_bytes).to_bytes(4, 'big'))
            client_socket.send(server_ecdsa_public_bytes)
            print("   ✓ Sent ECDSA public key")

            # Send other server blocks
            for block in server_blocks[2:]:
                client_socket.send(block)
            print("   ✓ Sent additional server blocks")

            # Send signatures
            client_socket.send(len(ecdsa_signature).to_bytes(4, 'big'))
            client_socket.send(ecdsa_signature)
            client_socket.send(len(openssl_signature).to_bytes(4, 'big'))
            client_socket.send(openssl_signature)
            print("   ✓ Sent both signatures")

            print("\n8. Completing key exchange:")
            # Complete ECDHE key exchange
            shared_secret = KeyExchange.generate_shared_secret(private_key, client_public_key)
            symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
            print("   ✓ Generated shared secret")
            print(f"   ✓ Derived symmetric key (length: {len(symmetric_key)} bytes)")
            print("   ✓ Key exchange completed successfully")
            print("=== SERVER KEY EXCHANGE COMPLETE ===\n")

            return symmetric_key

        except Exception as e:
            print(f"\n❌ SERVER ERROR: Key exchange failed: {str(e)}")
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def broadcast(self, message, sender_socket):
        try:
            sender_ip, sender_port = self.clients[sender_socket]["address"]
            sender_rooms = self.clients[sender_socket]["rooms"]

            print(f"\nBroadcasting message in rooms: {sender_rooms}")
            print(f"From: {sender_ip}:{sender_port}")
            print(f"Message: {message}")

            for room_name in sender_rooms:
                formatted_message = f"[{room_name}] {sender_ip}:{sender_port}: {message}"
                self.update_text_widget(formatted_message + "\n")

                if room_name not in self.rooms:
                    print(f"Room {room_name} not found!")
                    continue

                recipients = [client for client in self.rooms[room_name] if client != sender_socket]
                print(f"Recipients in room {room_name}: {len(recipients)}")

                for client_socket in recipients:
                    try:
                        symmetric_key = self.clients[client_socket]["symmetric_key"]
                        encrypted_message = AESGCMCipher.encrypt(symmetric_key, formatted_message)
                        encoded_message = base64.b64encode(encrypted_message)

                        # Send message length first
                        message_length = len(encoded_message).to_bytes(4, 'big')
                        client_socket.send(message_length)

                        # Send message in chunks
                        total_sent = 0
                        while total_sent < len(encoded_message):
                            sent = client_socket.send(encoded_message[total_sent:])
                            if sent == 0:
                                raise ConnectionError("Socket connection broken")
                            total_sent += sent

                        print(f"Message sent to {self.clients[client_socket]['address']}")

                    except Exception as e:
                        print(f"Failed to send to client: {e}")
                        self.update_text_widget(f"Error broadcasting message: {str(e)}\n")

        except Exception as e:
            print(f"Broadcast error: {e}")
            self.update_text_widget(f"Broadcast error: {str(e)}\n")

    def broadcast_system_message(self, message, room_name):
        system_message = f"[SYSTEM] {message}"
        if room_name in self.rooms:
            for client_socket in self.rooms[room_name]:
                try:
                    symmetric_key = self.clients[client_socket]["symmetric_key"]
                    encrypted_message = AESGCMCipher.encrypt(symmetric_key, system_message)

                    # Send encrypted message in blocks
                    encoded_message = base64.b64encode(encrypted_message)
                    for i in range(0, len(encoded_message), SecurityConstants.BLOCK_SIZE):
                        block = encoded_message[i:i + SecurityConstants.BLOCK_SIZE]
                        client_socket.send(block)

                except Exception as e:
                    self.update_text_widget(f"Error sending system message: {str(e)}\n")

    def stop(self):
        if messagebox.askyesno("Confirm Stop", "Are you sure you want to stop the server?"):
            self.is_running = False

            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
                self.server_socket = None

            for client_socket in list(self.clients.keys()):
                self.disconnect_client(client_socket)

            if self.accept_thread and self.accept_thread.is_alive():
                self.accept_thread.join(timeout=1.0)

            self.update_text_widget("Server stopped.\n")
            self.status_label.config(text="Server Status: Stopped")

            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.host_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)

            self.stats = {
                "total_connections": 0,
                "active_connections": 0,
                "total_messages": 0,
                "start_time": None
            }

    def disconnect_client(self, client_socket):
        if client_socket in self.clients:
            ip, port = self.clients[client_socket]["address"]

            for room_name in list(self.clients[client_socket]["rooms"]):
                self.leave_room(client_socket, room_name)

            self.stats["active_connections"] -= 1

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

            join_message = f"User {ip}:{port} has joined the room."
            self.broadcast_system_message(join_message, room_name)

            self.root.after(0, lambda: (self.update_client_list(), self.update_rooms_list()))

    def leave_room(self, client_socket, room_name):
        if room_name in self.rooms and client_socket in self.rooms[room_name]:
            ip, port = self.clients[client_socket]["address"]

            self.rooms[room_name].remove(client_socket)
            self.clients[client_socket]["rooms"].remove(room_name)

            self.update_text_widget(f"Client {ip}:{port} left room: {room_name}\n")

            leave_message = f"User {ip}:{port} has left the room."
            self.broadcast_system_message(leave_message, room_name)

            if not self.rooms[room_name]:
                del self.rooms[room_name]
                self.update_text_widget(f"Room '{room_name}' has been closed (no active users)\n")

            self.root.after(0, lambda: (self.update_client_list(), self.update_rooms_list()))

    def update_text_widget(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"

        self.text_widget.configure(state=tk.NORMAL)
        self.text_widget.insert(tk.END, formatted_message)
        self.text_widget.configure(state=tk.DISABLED)
        self.text_widget.see(tk.END)

    def update_client_list(self):
        for item in self.clients_tree.get_children():
            self.clients_tree.delete(item)

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
        for item in self.rooms_tree.get_children():
            self.rooms_tree.delete(item)

        for room_name, clients in self.rooms.items():
            self.rooms_tree.insert("", tk.END, values=(
                room_name,
                len(clients),
                self.get_room_message_count(room_name)
            ))

    def get_room_message_count(self, room_name):
        return "N/A"

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

        if messagebox.askyesno("Confirm Disconnect",
                               "Are you sure you want to disconnect the selected client?"):
            for item in selection:
                values = self.clients_tree.item(item)['values']
                ip, port = values[0], values[1]

                for client_socket, client_data in self.clients.items():
                    if client_data["address"] == (ip, int(port)):
                        self.disconnect_client(client_socket)
                        break

    def disconnect_all_clients(self):
        if not self.clients:
            messagebox.showinfo("Info", "No clients connected")
            return

        if messagebox.askyesno("Confirm Disconnect All",
                               "Are you sure you want to disconnect all clients?"):
            for client_socket in list(self.clients.keys()):
                self.disconnect_client(client_socket)

    def close_selected_room(self):
        selection = self.rooms_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a room to close")
            return

        if messagebox.askyesno("Confirm Close Room",
                               "Are you sure you want to close the selected room?"):
            for item in selection:
                values = self.rooms_tree.item(item)['values']
                room_name = values[0]

                if room_name in self.rooms:
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

    def export_logs(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"server_log_{timestamp}.txt"

            with open(filename, "w") as f:
                f.write(self.text_widget.get("1.0", tk.END))

            messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {str(e)}")

    def show_server_info(self):
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

    def on_closing(self):
        if self.is_running:
            if messagebox.askyesno("Quit", "Server is running. Stop server and quit?"):
                self.stop()
                self.root.destroy()
        else:
            self.root.destroy()

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


if __name__ == "__main__":
    server_gui = ModernServerGUI()
    server_gui.run()
