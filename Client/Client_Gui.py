import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import base64
from cryptography.hazmat.primitives import serialization
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.AES_GCM_CYPHER import AESGCMCipher


class ClientGUI:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.connected = False
        self.symmetric_key = None
        self.rooms = []

        self.root = tk.Tk()
        self.root.title("Enhanced Chat Client")
        self.root.geometry("800x600")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#333")
        self.style.configure("TLabel", background="#333", foreground="white")
        self.style.configure("TButton", background="#555", foreground="white")
        self.style.configure("TListbox", background="#222", foreground="white")

        # Main frame
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(expand=True, fill=tk.BOTH)

        # Connection settings
        connection_frame = ttk.Frame(self.main_frame)
        connection_frame.pack(fill=tk.X, pady=5)

        ttk.Label(connection_frame, text="Server IP:").pack(side=tk.LEFT, padx=5)
        self.ip_entry = ttk.Entry(connection_frame, width=15)
        self.ip_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(connection_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_entry = ttk.Entry(connection_frame, width=5)
        self.port_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(connection_frame, text="Username:").pack(side=tk.LEFT, padx=5)
        self.username_entry = ttk.Entry(connection_frame, width=15)
        self.username_entry.pack(side=tk.LEFT, padx=5)

        self.connect_button = ttk.Button(connection_frame, text="Connect", command=self.connect)
        self.connect_button.pack(side=tk.LEFT, padx=5)

        # Chat log
        ttk.Label(self.main_frame, text="Chat Log:").pack(anchor=tk.W, pady=5)
        self.chat_log = tk.Text(self.main_frame, wrap=tk.WORD, state=tk.DISABLED, height=15)
        self.chat_log.pack(expand=True, fill=tk.BOTH, pady=5)

        # Message input
        input_frame = ttk.Frame(self.main_frame)
        input_frame.pack(fill=tk.X, pady=5)

        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.message_entry.config(state=tk.DISABLED)

        self.send_button = ttk.Button(input_frame, text="Send", command=self.send_message, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=5)

        # Room management
        ttk.Label(self.main_frame, text="Room Management:").pack(anchor=tk.W, pady=5)
        room_frame = ttk.Frame(self.main_frame)
        room_frame.pack(fill=tk.BOTH, pady=5)

        self.room_list = tk.Listbox(room_frame, height=10)
        self.room_list.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)

        room_button_frame = ttk.Frame(room_frame)
        room_button_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        self.room_entry = ttk.Entry(room_button_frame, width=20)
        self.room_entry.pack(pady=5)

        self.join_room_button = ttk.Button(room_button_frame, text="Join Room", command=self.join_room)
        self.join_room_button.pack(fill=tk.X, pady=5)

        self.leave_room_button = ttk.Button(room_button_frame, text="Leave Room", command=self.leave_room)
        self.leave_room_button.pack(fill=tk.X, pady=5)

    def perform_key_exchange(self):
        self.private_key, self.public_key = KeyExchange.generate_key_pair()
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.client_socket.send(public_key_bytes)
        server_public_key_bytes = self.client_socket.recv(32)
        server_public_key = KeyExchange.deserialize_public_key(server_public_key_bytes)
        shared_secret = KeyExchange.generate_shared_secret(self.private_key, server_public_key)
        self.symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)

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

                self.chat_log.config(state=tk.NORMAL)
                self.chat_log.insert(tk.END, f"Connected to {server_ip}:{server_port}\n")
                self.chat_log.config(state=tk.DISABLED)

                self.username_entry.config(state=tk.DISABLED)
                self.connect_button.config(state=tk.DISABLED)
                self.message_entry.config(state=tk.NORMAL)
                self.send_button.config(state=tk.NORMAL)
                self.connected = True

                threading.Thread(target=self.receive_messages, daemon=True).start()
            except Exception as e:
                messagebox.showerror("Connection Error", str(e))

    def send_message(self):
        message = self.message_entry.get()
        if message:
            if not self.rooms:
                self.chat_log.config(state=tk.NORMAL)
                self.chat_log.insert(tk.END, "Join a room first using the Room Management panel.\n")
                self.chat_log.config(state=tk.DISABLED)
                return

            formatted_message = f"{self.username}: {message}"
            self.chat_log.config(state=tk.NORMAL)
            self.chat_log.insert(tk.END, formatted_message + "\n")
            self.chat_log.config(state=tk.DISABLED)

            self.client_socket.send(self.encrypt_message(formatted_message))
            self.message_entry.delete(0, tk.END)

    def join_room(self):
        room_name = self.room_entry.get().strip()
        if room_name and room_name not in self.rooms:
            self.rooms.append(room_name)
            self.room_list.insert(tk.END, room_name)
            self.client_socket.send(self.encrypt_message(f"/join {room_name}"))
            self.chat_log.config(state=tk.NORMAL)
            self.chat_log.insert(tk.END, f"Joined room: {room_name}\n")
            self.chat_log.config(state=tk.DISABLED)

    def leave_room(self):
        selected_room = self.room_list.get(tk.ACTIVE)
        if selected_room:
            self.rooms.remove(selected_room)
            self.room_list.delete(tk.ANCHOR)
            self.client_socket.send(self.encrypt_message(f"/leave {selected_room}"))
            self.chat_log.config(state=tk.NORMAL)
            self.chat_log.insert(tk.END, f"Left room: {selected_room}\n")
            self.chat_log.config(state=tk.DISABLED)

    def receive_messages(self):
        try:
            while True:
                encrypted_data = self.client_socket.recv(1024)
                if not encrypted_data:
                    break

                decoded_data = base64.b64decode(encrypted_data)
                decrypted_message = AESGCMCipher.decrypt(self.symmetric_key, decoded_data)
                self.chat_log.config(state=tk.NORMAL)
                self.chat_log.insert(tk.END, decrypted_message + "\n")
                self.chat_log.config(state=tk.DISABLED)
        except Exception as e:
            self.chat_log.config(state=tk.NORMAL)
            self.chat_log.insert(tk.END, f"Error: {str(e)}\n")
            self.chat_log.config(state=tk.DISABLED)
        finally:
            self.client_socket.close()

    def encrypt_message(self, message):
        encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, message)
        return base64.b64encode(encrypted_message)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    client_gui = ClientGUI()
    client_gui.run()
