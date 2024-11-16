import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import base64
from cryptography.hazmat.primitives import serialization
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.AES_GCM_CYPHER import AESGCMCipher


class ServerGUI:
    def __init__(self):
        self.host = None
        self.port = 8080
        self.server_socket = None
        self.clients = {}
        self.rooms = {}

        self.root = tk.Tk()
        self.root.title("Chat Server")
        self.root.geometry("800x500")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#444")
        self.style.configure("TLabel", background="#444", foreground="white")
        self.style.configure("TButton", background="#555", foreground="white")
        self.style.configure("TListbox", background="#222", foreground="white")

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        server_frame = ttk.Frame(main_frame)
        server_frame.pack(fill=tk.X, pady=5)

        ttk.Label(server_frame, text="Server IP:").pack(side=tk.LEFT, padx=5)
        self.host_entry = ttk.Entry(server_frame)
        self.host_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.start_button = ttk.Button(server_frame, text="Start Server", command=self.start)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(server_frame, text="Stop Server", command=self.stop, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Label(main_frame, text="Server Log:").pack(anchor=tk.W, pady=5)
        self.text_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state=tk.DISABLED, height=15)
        self.text_widget.pack(expand=True, fill=tk.BOTH, pady=5)

        ttk.Label(main_frame, text="Connected Clients:").pack(anchor=tk.W, pady=5)
        self.client_list = tk.Listbox(main_frame, height=5)
        self.client_list.pack(expand=True, fill=tk.BOTH, pady=5)

    def start(self):
        self.host = self.host_entry.get()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.update_text_widget(f"Server started at {self.host}:{self.port}\n")
            threading.Thread(target=self.run_server, daemon=True).start()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        except Exception as e:
            self.update_text_widget(f"Failed to start server: {e}\n")

    def stop(self):
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        self.update_text_widget("Server stopped.\n")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def run_server(self):
        while True:
            try:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()
            except Exception as e:
                self.update_text_widget(f"Error accepting client: {e}\n")

    def handle_client(self, client_socket, client_address):
        try:
            ip, port = client_address
            self.update_text_widget(f"Client connected: {ip}:{port}\n")

            symmetric_key = self.perform_key_exchange(client_socket)
            self.clients[client_socket] = {"address": client_address, "symmetric_key": symmetric_key, "rooms": []}

            self.root.after(0, self.update_client_list)

            while True:
                try:
                    encrypted_data = client_socket.recv(1024)
                    if not encrypted_data:
                        break

                    decoded_data = base64.b64decode(encrypted_data)
                    decrypted_message = AESGCMCipher.decrypt(symmetric_key, decoded_data)

                    if decrypted_message.startswith("/join "):
                        room_name = decrypted_message.split(" ", 1)[1].strip()
                        self.join_room(client_socket, room_name)
                    elif decrypted_message.startswith("/leave "):
                        room_name = decrypted_message.split(" ", 1)[1].strip()
                        self.leave_room(client_socket, room_name)
                    else:
                        self.broadcast(decrypted_message, client_socket)
                except Exception as e:
                    self.update_text_widget(f"Error with client {ip}:{port}: {e}\n")
                    break
        finally:
            self.disconnect_client(client_socket)

    def perform_key_exchange(self, client_socket):
        private_key, public_key = KeyExchange.generate_key_pair()
        client_public_key_bytes = client_socket.recv(32)
        client_public_key = KeyExchange.deserialize_public_key(client_public_key_bytes)

        client_socket.send(
            public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )

        shared_secret = KeyExchange.generate_shared_secret(private_key, client_public_key)
        symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
        return symmetric_key

    def join_room(self, client_socket, room_name):
        if room_name not in self.rooms:
            self.rooms[room_name] = []
        if client_socket not in self.rooms[room_name]:
            self.rooms[room_name].append(client_socket)
            self.clients[client_socket]["rooms"].append(room_name)
            self.update_text_widget(f"Client joined room: {room_name}\n")

    def leave_room(self, client_socket, room_name):
        if room_name in self.rooms and client_socket in self.rooms[room_name]:
            self.rooms[room_name].remove(client_socket)
            self.clients[client_socket]["rooms"].remove(room_name)
            self.update_text_widget(f"Client left room: {room_name}\n")
            if not self.rooms[room_name]:
                del self.rooms[room_name]

    def broadcast(self, message, sender_socket):
        sender_rooms = self.clients[sender_socket]["rooms"]
        for room_name in sender_rooms:
            for client_socket in self.rooms[room_name]:
                if client_socket != sender_socket:
                    symmetric_key = self.clients[client_socket]["symmetric_key"]
                    encrypted_message = AESGCMCipher.encrypt(symmetric_key, message)
                    client_socket.send(base64.b64encode(encrypted_message))

    def disconnect_client(self, client_socket):
        if client_socket in self.clients:
            for room_name in list(self.clients[client_socket]["rooms"]):
                self.leave_room(client_socket, room_name)
            del self.clients[client_socket]
            client_socket.close()
            self.update_text_widget("Client disconnected.\n")
            self.root.after(0, self.update_client_list)

    def update_text_widget(self, message):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, message)
        self.text_widget.config(state=tk.DISABLED)
        self.text_widget.yview(tk.END)

    def update_client_list(self):
        self.client_list.delete(0, tk.END)
        for client_socket, client_data in self.clients.items():
            ip, port = client_data["address"]
            self.client_list.insert(tk.END, f"{ip}:{port}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    server_gui = ServerGUI()
    server_gui.run()
