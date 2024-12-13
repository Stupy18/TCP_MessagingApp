import customtkinter as ctk
from tkinter import messagebox
import socket
import threading
import base64
from cryptography.hazmat.primitives import serialization
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.AES_GCM_CYPHER import AESGCMCipher
from datetime import datetime


class ModernServerGUI:
    def __init__(self):
        self.host = None
        self.port = 8080
        self.server_socket = None
        self.clients = {}
        self.rooms = {}
        self.is_running = False

        # Configure appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Main window setup
        self.root = ctk.CTk()
        self.root.title("Secure Chat Server Dashboard")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Create main container with padding
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(expand=True, fill="both", padx=10, pady=10)

        # Create layout
        self.create_header_frame()
        self.create_main_content()
        self.create_status_bar()
        self.create_menu()

        # Initialize statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_messages": 0,
            "start_time": None
        }

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_header_frame(self):
        header_frame = ctk.CTkFrame(self.main_container)
        header_frame.pack(fill="x", pady=(0, 10))

        # Server controls
        controls_frame = ctk.CTkFrame(header_frame)
        controls_frame.pack(side="left", padx=10, pady=5)

        # IP input
        ctk.CTkLabel(controls_frame, text="Server IP:").pack(side="left", padx=5)
        self.host_entry = ctk.CTkEntry(controls_frame, width=120)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(side="left", padx=5)

        # Port input
        ctk.CTkLabel(controls_frame, text="Port:").pack(side="left", padx=5)
        self.port_entry = ctk.CTkEntry(controls_frame, width=80)
        self.port_entry.insert(0, str(self.port))
        self.port_entry.pack(side="left", padx=5)

        # Control buttons
        self.start_button = ctk.CTkButton(
            controls_frame,
            text="Start Server",
            command=self.start,
            fg_color="green",
            hover_color="dark green"
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            controls_frame,
            text="Stop Server",
            command=self.stop,
            fg_color="red",
            hover_color="dark red",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        # Server status
        self.status_label = ctk.CTkLabel(
            header_frame,
            text="Server Status: Stopped",
            font=("Helvetica", 12, "bold")
        )
        self.status_label.pack(side="right", padx=10)

    def create_main_content(self):
        # Create tabview
        self.tabview = ctk.CTkTabview(self.main_container)
        self.tabview.pack(expand=True, fill="both", pady=5)

        # Server Log Tab
        log_tab = self.tabview.add("Server Log")

        log_controls = ctk.CTkFrame(log_tab)
        log_controls.pack(fill="x", pady=5)

        ctk.CTkButton(
            log_controls,
            text="Export Logs",
            command=self.export_logs,
            fg_color="blue",
            hover_color="dark blue"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            log_controls,
            text="Clear Logs",
            command=self.clear_logs,
            fg_color="red",
            hover_color="dark red"
        ).pack(side="left", padx=5)

        # Log text area
        self.text_widget = ctk.CTkTextbox(
            log_tab,
            wrap="word",
            font=("Consolas", 12)
        )
        self.text_widget.pack(expand=True, fill="both", padx=5, pady=5)

        # Clients Tab
        clients_tab = self.tabview.add("Connected Clients")

        clients_controls = ctk.CTkFrame(clients_tab)
        clients_controls.pack(fill="x", pady=5)

        ctk.CTkButton(
            clients_controls,
            text="Disconnect Selected",
            command=self.disconnect_selected_client,
            fg_color="red",
            hover_color="dark red"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            clients_controls,
            text="Disconnect All",
            command=self.disconnect_all_clients,
            fg_color="red",
            hover_color="dark red"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            clients_controls,
            text="Refresh List",
            command=self.update_client_list,
            fg_color="blue",
            hover_color="dark blue"
        ).pack(side="left", padx=5)

        # Clients list
        self.clients_frame = ctk.CTkScrollableFrame(clients_tab)
        self.clients_frame.pack(expand=True, fill="both", padx=5, pady=5)

        # Create headers for clients list
        self.create_list_headers(
            self.clients_frame,
            ["IP", "Port", "Connected Time", "Active Rooms"]
        )

        # Rooms Tab
        rooms_tab = self.tabview.add("Chat Rooms")

        rooms_controls = ctk.CTkFrame(rooms_tab)
        rooms_controls.pack(fill="x", pady=5)

        ctk.CTkButton(
            rooms_controls,
            text="Close Selected Room",
            command=self.close_selected_room,
            fg_color="red",
            hover_color="dark red"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            rooms_controls,
            text="Close All Rooms",
            command=self.close_all_rooms,
            fg_color="red",
            hover_color="dark red"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            rooms_controls,
            text="Refresh Rooms",
            command=self.update_rooms_list,
            fg_color="blue",
            hover_color="dark blue"
        ).pack(side="left", padx=5)

        # Rooms list
        self.rooms_frame = ctk.CTkScrollableFrame(rooms_tab)
        self.rooms_frame.pack(expand=True, fill="both", padx=5, pady=5)

        # Create headers for rooms list
        self.create_list_headers(
            self.rooms_frame,
            ["Room Name", "Active Users", "Messages"]
        )

    def export_logs(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"server_log_{timestamp}.txt"

            with open(filename, "w") as f:
                f.write(self.text_widget.get("1.0", "end"))

            messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {str(e)}")

    def clear_logs(self):
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear the logs?"):
            self.text_widget.configure(state="normal")
            self.text_widget.delete("1.0", "end")
            self.text_widget.configure(state="disabled")

    def disconnect_selected_client(self):
        # Since we're not using a treeview anymore, we'll need to implement a selection mechanism
        messagebox.showwarning("Not Implemented", "Client selection not implemented in this version")

    def disconnect_all_clients(self):
        if not self.clients:
            messagebox.showinfo("Info", "No clients connected")
            return

        if messagebox.askyesno("Confirm Disconnect All", "Are you sure you want to disconnect all clients?"):
            for client_socket in list(self.clients.keys()):
                self.disconnect_client(client_socket)

    def close_selected_room(self):
        # Since we're not using a treeview anymore, we'll need to implement a selection mechanism
        messagebox.showwarning("Not Implemented", "Room selection not implemented in this version")

    def close_all_rooms(self):
        if not self.rooms:
            messagebox.showinfo("Info", "No active rooms")
            return

        if messagebox.askyesno("Confirm Close All", "Are you sure you want to close all rooms?"):
            room_names = list(self.rooms.keys())
            for room_name in room_names:
                for client_socket in self.rooms[room_name][:]:
                    self.leave_room(client_socket, room_name)

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
                    encrypted_message = AESGCMCipher.encrypt(symmetric_key, system_message)
                    client_socket.send(base64.b64encode(encrypted_message))
                except Exception as e:
                    self.update_text_widget(f"Error sending system message: {str(e)}\n")

    def broadcast(self, message, sender_socket):
        sender_ip, sender_port = self.clients[sender_socket]["address"]
        sender_rooms = self.clients[sender_socket]["rooms"]

        for room_name in sender_rooms:
            formatted_message = f"[{room_name}] {sender_ip}:{sender_port}: {message}"
            self.update_text_widget(formatted_message + "\n")

            for client_socket in self.rooms[room_name]:
                if client_socket != sender_socket:
                    try:
                        symmetric_key = self.clients[client_socket]["symmetric_key"]
                        encrypted_message = AESGCMCipher.encrypt(symmetric_key, formatted_message)
                        client_socket.send(base64.b64encode(encrypted_message))
                    except Exception as e:
                        self.update_text_widget(f"Error broadcasting message: {str(e)}\n")
    def create_list_headers(self, parent, headers):
        header_frame = ctk.CTkFrame(parent)
        header_frame.pack(fill="x", padx=5, pady=5)

        for i, header in enumerate(headers):
            ctk.CTkLabel(
                header_frame,
                text=header,
                font=("Helvetica", 12, "bold")
            ).grid(row=0, column=i, padx=5, sticky="w")
            header_frame.grid_columnconfigure(i, weight=1)

    def create_status_bar(self):
        status_bar = ctk.CTkFrame(self.main_container)
        status_bar.pack(fill="x", side="bottom", pady=(5, 0))

        self.connection_count = ctk.CTkLabel(
            status_bar,
            text="Connections: 0"
        )
        self.connection_count.pack(side="left", padx=10)

        self.message_count = ctk.CTkLabel(
            status_bar,
            text="Messages: 0"
        )
        self.message_count.pack(side="left", padx=10)

        self.uptime_label = ctk.CTkLabel(
            status_bar,
            text="Uptime: 0:00:00"
        )
        self.uptime_label.pack(side="right", padx=10)

    def create_menu(self):
        self.menu_bar = ctk.CTkFrame(self.root, height=30)
        self.menu_bar.pack(fill="x", padx=5, pady=(5, 0))

        # File menu button
        self.file_menu = ctk.CTkButton(
            self.menu_bar,
            text="File",
            width=60,
            height=24,
            command=self.show_file_menu
        )
        self.file_menu.pack(side="left", padx=2)

        # Server menu button
        self.server_menu = ctk.CTkButton(
            self.menu_bar,
            text="Server",
            width=60,
            height=24,
            command=self.show_server_menu
        )
        self.server_menu.pack(side="left", padx=2)

        # Clients menu button
        self.clients_menu = ctk.CTkButton(
            self.menu_bar,
            text="Clients",
            width=60,
            height=24,
            command=self.show_clients_menu
        )
        self.clients_menu.pack(side="left", padx=2)

        # Rooms menu button
        self.rooms_menu = ctk.CTkButton(
            self.menu_bar,
            text="Rooms",
            width=60,
            height=24,
            command=self.show_rooms_menu
        )
        self.rooms_menu.pack(side="left", padx=2)

    def show_file_menu(self):
        menu = ctk.CTkToplevel(self.root)
        menu.geometry("200x250")
        menu.title("File Menu")

        ctk.CTkButton(menu, text="Export Logs", command=self.export_logs).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(menu, text="Clear Logs", command=self.clear_logs).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(menu, text="Exit", command=self.on_closing).pack(pady=5, padx=10, fill="x")

    def show_server_menu(self):
        menu = ctk.CTkToplevel(self.root)
        menu.geometry("200x250")
        menu.title("Server Menu")

        ctk.CTkButton(menu, text="Start Server", command=self.start).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(menu, text="Stop Server", command=self.stop).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(menu, text="Server Information", command=self.show_server_info).pack(pady=5, padx=10, fill="x")

    def show_clients_menu(self):
        menu = ctk.CTkToplevel(self.root)
        menu.geometry("200x250")
        menu.title("Clients Menu")

        ctk.CTkButton(menu, text="Disconnect Selected", command=self.disconnect_selected_client).pack(pady=5, padx=10,
                                                                                                      fill="x")
        ctk.CTkButton(menu, text="Disconnect All", command=self.disconnect_all_clients).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(menu, text="Refresh List", command=self.update_client_list).pack(pady=5, padx=10, fill="x")

    def show_rooms_menu(self):
        menu = ctk.CTkToplevel(self.root)
        menu.geometry("200x250")
        menu.title("Rooms Menu")

        ctk.CTkButton(menu, text="Close Selected Room", command=self.close_selected_room).pack(pady=5, padx=10,
                                                                                               fill="x")
        ctk.CTkButton(menu, text="Close All Rooms", command=self.close_all_rooms).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(menu, text="Refresh Rooms", command=self.update_rooms_list).pack(pady=5, padx=10, fill="x")

    def update_client_list(self):
        # Clear existing items
        for widget in self.clients_frame.winfo_children()[1:]:  # Skip headers
            widget.destroy()

        # Add current clients
        for i, (client_socket, client_data) in enumerate(self.clients.items()):
            ip, port = client_data["address"]
            connected_time = datetime.now() - client_data.get("connect_time", datetime.now())
            rooms = ", ".join(client_data["rooms"]) or "None"

            row_frame = ctk.CTkFrame(self.clients_frame)
            row_frame.pack(fill="x", padx=5, pady=2)

            # Use grid to align with headers
            ctk.CTkLabel(row_frame, text=ip).grid(row=0, column=0, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=str(port)).grid(row=0, column=1, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=str(connected_time).split(".")[0]).grid(row=0, column=2, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=rooms).grid(row=0, column=3, padx=5, sticky="w")

        # Configure grid columns
        for j in range(4):
            row_frame.grid_columnconfigure(j, weight=1)

    def update_rooms_list(self):
        # Clear existing items
        for widget in self.rooms_frame.winfo_children()[1:]:  # Skip headers
            widget.destroy()

        # Add current rooms
        for room_name, clients in self.rooms.items():
            row_frame = ctk.CTkFrame(self.rooms_frame)
            row_frame.pack(fill="x", padx=5, pady=2)

            # Use grid to align with headers
            ctk.CTkLabel(row_frame, text=room_name).grid(row=0, column=0, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=str(len(clients))).grid(row=0, column=1, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=self.get_room_message_count(room_name)).grid(row=0, column=2, padx=5,
                                                                                      sticky="w")

            # Configure grid columns
            for j in range(3):
                row_frame.grid_columnconfigure(j, weight=1)

    def update_text_widget(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"

        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", formatted_message)
        self.text_widget.configure(state="disabled")
        self.text_widget.see("end")

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
            self.status_label.configure(text="Server Status: Running")

            # Create a separate thread for accepting connections
            self.accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            self.accept_thread.start()

            self.update_status_bar()

            # Update UI states
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.host_entry.configure(state="disabled")
            self.port_entry.configure(state="disabled")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
            self.update_text_widget(f"Failed to start server: {str(e)}\n")

    def stop(self):
        if not messagebox.askyesno("Confirm Stop", "Are you sure you want to stop the server?"):
            return

        self.is_running = False

        # Close the server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None

        # Disconnect all clients
        for client_socket in list(self.clients.keys()):
            self.disconnect_client(client_socket)

        # Wait for accept thread to finish
        if hasattr(self, 'accept_thread') and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=1.0)

        self.update_text_widget("Server stopped.\n")
        self.status_label.configure(text="Server Status: Stopped")

        # Reset UI states
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.host_entry.configure(state="normal")
        self.port_entry.configure(state="normal")

        # Reset statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_messages": 0,
            "start_time": None
        }

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

                except Exception as e:
                    self.update_text_widget(f"Error with client {ip}:{port}: {str(e)}\n")
                    break

        finally:
            self.disconnect_client(client_socket)

    def perform_key_exchange(self, client_socket):
        try:
            private_key, public_key = KeyExchange.generate_key_pair()

            # Receive client's public key
            client_public_key_bytes = client_socket.recv(32)
            client_public_key = KeyExchange.deserialize_public_key(client_public_key_bytes)

            # Send server's public key
            server_public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            client_socket.send(server_public_bytes)

            # Generate shared secret and derive symmetric key
            shared_secret = KeyExchange.generate_shared_secret(private_key, client_public_key)
            symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)

            return symmetric_key

        except Exception as e:
            self.update_text_widget(f"Error during key exchange: {str(e)}\n")
            raise

    def disconnect_client(self, client_socket):
        if client_socket in self.clients:
            ip, port = self.clients[client_socket]["address"]

            # Leave all rooms
            for room_name in list(self.clients[client_socket]["rooms"]):
                self.leave_room(client_socket, room_name)

            self.stats["active_connections"] -= 1
            del self.clients[client_socket]
            client_socket.close()

            self.update_text_widget(f"Client disconnected: {ip}:{port}\n")
            self.root.after(0, lambda: (self.update_client_list(), self.update_rooms_list()))

        # Rest of the functionality methods remain the same
        # broadcast(), join_room(), leave_room(), etc.

    def update_status_bar(self):
        if self.is_running:
            self.connection_count.configure(
                text=f"Active Connections: {self.stats['active_connections']}"
            )
            self.message_count.configure(
                text=f"Total Messages: {self.stats['total_messages']}"
            )

            if self.stats["start_time"]:
                uptime = datetime.now() - self.stats["start_time"]
                hours = uptime.seconds // 3600
                minutes = (uptime.seconds % 3600) // 60
                seconds = uptime.seconds % 60
                self.uptime_label.configure(
                    text=f"Uptime: {hours}:{minutes:02d}:{seconds:02d}"
                )

            self.root.after(1000, self.update_status_bar)

    def get_room_message_count(self, room_name):
        return "N/A"  # Could be enhanced to track messages per room

    def on_closing(self):
        if self.is_running:
            if messagebox.askyesno("Quit", "Server is running. Stop server and quit?"):
                self.stop()
                self.root.destroy()
        else:
            self.root.destroy()

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


    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    server_gui = ModernServerGUI()
    server_gui.run()
