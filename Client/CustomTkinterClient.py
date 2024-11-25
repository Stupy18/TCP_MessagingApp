import customtkinter as ctk
import socket
import threading
import base64
from cryptography.hazmat.primitives import serialization
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.AES_GCM_CYPHER import AESGCMCipher
from tkinter import messagebox


class ClientGUI:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.connected = False
        self.symmetric_key = None
        self.rooms = []

        # Window Setup
        self.root = ctk.CTk()
        self.root.title("Secure Chat")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Create main container
        self.container = ctk.CTkFrame(self.root)
        self.container.pack(expand=True, fill='both', padx=10, pady=10)

        # Create sections
        self.create_header_section()
        self.create_main_section()
        self.create_status_bar()
        self.setup_bindings()
        self.setup_hover_effects()

    def setup_hover_effects(self):
        def on_enter(e):
            e.widget.configure(fg_color=("gray75", "gray30"))

        def on_leave(e):
            e.widget.configure(fg_color=("gray70", "gray25"))

        for button in [self.connect_button, self.send_button]:
            button.bind('<Enter>', on_enter)
            button.bind('<Leave>', on_leave)

    def create_header_section(self):
        header = ctk.CTkFrame(self.container)
        header.pack(fill='x', pady=(0, 15))

        # Connection settings frame
        settings_frame = ctk.CTkFrame(header)
        settings_frame.pack(expand=True, fill='x')

        # IP Input
        ip_label = ctk.CTkLabel(settings_frame, text="Server IP")
        ip_label.grid(row=0, column=0, padx=(10, 5), pady=5, sticky='w')
        self.ip_entry = ctk.CTkEntry(settings_frame, width=150)
        self.ip_entry.grid(row=1, column=0, padx=(10, 5), pady=(0, 10))
        self.ip_entry.insert(0, "127.0.0.1")

        # Port Input
        port_label = ctk.CTkLabel(settings_frame, text="Port")
        port_label.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        self.port_entry = ctk.CTkEntry(settings_frame, width=100)
        self.port_entry.grid(row=1, column=1, padx=5, pady=(0, 10))
        self.port_entry.insert(0, "8080")

        # Username Input
        username_label = ctk.CTkLabel(settings_frame, text="Username")
        username_label.grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.username_entry = ctk.CTkEntry(settings_frame, width=200)
        self.username_entry.grid(row=1, column=2, padx=5, pady=(0, 10))

        # Connect Button
        self.connect_button = ctk.CTkButton(
            settings_frame,
            text="Connect",
            command=self.connect,
            width=150
        )
        self.connect_button.grid(row=1, column=3, padx=10, pady=(0, 10))

    def create_main_section(self):
        main_content = ctk.CTkFrame(self.container)
        main_content.pack(expand=True, fill='both')

        # Chat Section
        chat_frame = ctk.CTkFrame(main_content)
        chat_frame.pack(side='left', expand=True, fill='both', padx=5, pady=5)

        chat_label = ctk.CTkLabel(
            chat_frame,
            text="MESSAGES",
            font=('Helvetica', 16, 'bold')
        )
        chat_label.pack(anchor='w', pady=(0, 10))

        self.chat_log = ctk.CTkTextbox(
            chat_frame,
            state='disabled',
            wrap='word',
            font=('Segoe UI', 11)
        )
        self.chat_log.pack(expand=True, fill='both', padx=5, pady=5)

        # Message input area
        input_frame = ctk.CTkFrame(chat_frame)
        input_frame.pack(fill='x', padx=5, pady=5)

        self.message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Type your message...",
            state='disabled',
            width=400
        )
        self.message_entry.pack(side='left', expand=True, fill='x', padx=(0, 10))

        self.send_button = ctk.CTkButton(
            input_frame,
            text="Send",
            command=self.send_message,
            state='disabled',
            width=100
        )
        self.send_button.pack(side='right')

        # Rooms Section
        rooms_frame = ctk.CTkFrame(main_content, width=250)
        rooms_frame.pack(side='right', fill='y', padx=5, pady=5)

        rooms_label = ctk.CTkLabel(
            rooms_frame,
            text="ROOMS",
            font=('Helvetica', 16, 'bold')
        )
        rooms_label.pack(anchor='w', pady=(0, 10))

        self.room_list = ctk.CTkScrollableFrame(rooms_frame)
        self.room_list.pack(expand=True, fill='both', padx=5, pady=5)

        room_control_frame = ctk.CTkFrame(rooms_frame)
        room_control_frame.pack(fill='x', padx=5, pady=5)

        self.room_entry = ctk.CTkEntry(
            room_control_frame,
            placeholder_text="Enter room name",
            width=200
        )
        self.room_entry.pack(side='left', expand=True, fill='x', padx=(0, 10))

        join_button = ctk.CTkButton(
            room_control_frame,
            text="Join",
            command=self.join_room,
            width=100
        )
        join_button.pack(side='right')

    def create_status_bar(self):
        self.status_bar = ctk.CTkLabel(
            self.container,
            text="Not connected",
            font=('Segoe UI', 10),
            fg_color=("gray85", "gray20"),
            corner_radius=5,
            pady=8
        )
        self.status_bar.pack(fill='x', pady=(10, 0))

    def setup_bindings(self):
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        self.room_entry.bind('<Return>', lambda e: self.join_room())

    def update_status(self, message, status_type='info'):
        self.status_bar.configure(text=message)
        if status_type == 'error':
            self.status_bar.configure(text_color='#F38BA8')
        elif status_type == 'success':
            self.status_bar.configure(text_color='#A6E3A1')
        else:
            self.status_bar.configure(text_color=("gray10", "gray90"))

    def connect(self):
        if not self.connected:
            try:
                server_ip = self.ip_entry.get()
                server_port = int(self.port_entry.get())
                self.client_socket.connect((server_ip, server_port))
                self.perform_key_exchange()

                self.username = self.username_entry.get()
                if not self.username:
                    raise ValueError("Username cannot be empty.")

                self.chat_log.configure(state='normal')
                self.chat_log.insert('end', f"Connected to {server_ip}:{server_port}\n")
                self.chat_log.configure(state='disabled')

                self.username_entry.configure(state='disabled')
                self.ip_entry.configure(state='disabled')
                self.port_entry.configure(state='disabled')
                self.connect_button.configure(state='disabled')
                self.message_entry.configure(state='normal')
                self.send_button.configure(state='normal')
                self.connected = True

                self.update_status(f"Connected as {self.username}", 'success')
                threading.Thread(target=self.receive_messages, daemon=True).start()

            except Exception as e:
                self.update_status(f"Connection error: {str(e)}", 'error')
                messagebox.showerror("Connection Error", str(e))

    def send_message(self):
        message = self.message_entry.get().strip()
        if message:
            if not self.rooms:
                self.update_status("Please join a room first", 'error')
                self.chat_log.configure(state='normal')
                self.chat_log.insert('end', "Join a room first using the Room Management panel.\n")
                self.chat_log.configure(state='disabled')
                return

            formatted_message = f"{self.username}: {message}"
            self.chat_log.configure(state='normal')
            self.chat_log.insert('end', formatted_message + "\n")
            self.chat_log.see('end')
            self.chat_log.configure(state='disabled')

            self.client_socket.send(self.encrypt_message(formatted_message))
            self.message_entry.delete(0, 'end')

    def join_room(self):
        room_name = self.room_entry.get().strip()
        if not room_name:
            self.update_status("Please enter a valid room name", 'error')
            return

        if room_name not in self.rooms:
            try:
                self.rooms.append(room_name)
                room_button = ctk.CTkButton(
                    self.room_list,
                    text=room_name,
                    command=lambda r=room_name: self.leave_room(r)
                )
                room_button.pack(fill='x', pady=5)

                self.client_socket.send(self.encrypt_message(f"/join {room_name}"))

                self.chat_log.configure(state='normal')
                self.chat_log.insert('end', f"→ Joined room: {room_name}\n")
                self.chat_log.see('end')
                self.chat_log.configure(state='disabled')

                self.room_entry.delete(0, 'end')
                self.update_status(f"Successfully joined room: {room_name}", 'success')
            except Exception as e:
                self.update_status(f"Failed to join room: {str(e)}", 'error')
                self.rooms.remove(room_name)

    def leave_room(self, room_name):
        try:
            self.rooms.remove(room_name)
            for widget in self.room_list.winfo_children():
                if isinstance(widget, ctk.CTkButton) and widget.cget("text") == room_name:
                    widget.destroy()

            self.client_socket.send(self.encrypt_message(f"/leave {room_name}"))

            self.chat_log.configure(state='normal')
            self.chat_log.insert('end', f"← Left room: {room_name}\n")
            self.chat_log.see('end')
            self.chat_log.configure(state='disabled')

            self.update_status(f"Successfully left room: {room_name}", 'success')
        except Exception as e:
            self.update_status(f"Failed to leave room: {str(e)}", 'error')

    def receive_messages(self):
        try:
            while True:
                encrypted_data = self.client_socket.recv(1024)
                if not encrypted_data:
                    raise ConnectionError("Server connection lost")

                decoded_data = base64.b64decode(encrypted_data)
                decrypted_message = AESGCMCipher.decrypt(self.symmetric_key, decoded_data)

                self.chat_log.configure(state='normal')
                self.chat_log.insert('end', decrypted_message + "\n")
                self.chat_log.see('end')
                self.chat_log.configure(state='disabled')
        except ConnectionError as e:
            self.handle_disconnect(str(e))
        except Exception as e:
            self.handle_disconnect(f"Error: {str(e)}")

    def handle_disconnect(self, error_message):
        self.connected = False
        self.chat_log.configure(state='normal')
        self.chat_log.insert('end', f"❌ {error_message}\n")
        self.chat_log.see('end')
        self.chat_log.configure(state='disabled')

        # Reset UI elements
        self.username_entry.configure(state='normal')
        self.ip_entry.configure(state='normal')
        self.port_entry.configure(state='normal')
        self.connect_button.configure(state='normal')
        self.message_entry.configure(state='disabled')
        self.send_button.configure(state='disabled')

        # Clear rooms
        for widget in self.room_list.winfo_children():
            widget.destroy()
        self.rooms.clear()

        self.update_status("Disconnected from server", 'error')

        try:
            self.client_socket.close()
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            pass

    def perform_key_exchange(self):
        try:
            self.private_key, self.public_key = KeyExchange.generate_key_pair()
            public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self.client_socket.send(public_key_bytes)

            server_public_key_bytes = self.client_socket.recv(32)
            if not server_public_key_bytes:
                raise ConnectionError("Failed to receive server's public key")

            server_public_key = KeyExchange.deserialize_public_key(server_public_key_bytes)
            shared_secret = KeyExchange.generate_shared_secret(self.private_key, server_public_key)
            self.symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)

            self.update_status("Secure connection established", 'success')
        except Exception as e:
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def encrypt_message(self, message):
        try:
            encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, message)
            return base64.b64encode(encrypted_message)
        except Exception as e:
            self.update_status(f"Encryption failed: {str(e)}", 'error')
            raise

    def run(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'+{x}+{y}')

        # Set window icon (if available)
        try:
            self.root.iconbitmap('chat_icon.ico')
        except:
            pass

        self.root.mainloop()

if __name__ == "__main__":
    try:
        client_gui = ClientGUI()
        client_gui.run()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application failed to start: {str(e)}")

