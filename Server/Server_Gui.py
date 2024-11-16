import tkinter as tk
import socket
import threading
from tkinter import ttk, scrolledtext
import base64
from cryptography.hazmat.primitives import serialization
from TLS.AES_GCM_CYPHER import AESGCMCipher
from TLS.KeyDerivation import KeyDerivation
from TLS.KeyExchange import KeyExchange


class ServerGUI:
    def __init__(self):
        self.host = None
        self.port = 8080
        self.server_socket = None
        self.clients = {}  # Stores client-specific data {socket: {"address": address, "symmetric_key": key, "room": room}}
        self.rooms = {}  # Stores rooms with their associated clients {room_name: [client_sockets]}
        self.chat_history = []

        self.root = tk.Tk()
        self.root.title("Chat Server")
        self.root.geometry("600x400")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#333")
        self.style.configure("TLabel", background="#333", foreground="white")
        self.style.configure("TButton", background="#333", foreground="white")

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        server_frame = ttk.Frame(main_frame)
        server_frame.pack(fill=tk.X)

        self.host_label = ttk.Label(server_frame, text="Enter Server IP:")
        self.host_label.pack(side=tk.LEFT, padx=5)

        self.host_entry = ttk.Entry(server_frame)
        self.host_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        self.start_button = ttk.Button(server_frame, text="Start Server", command=self.start)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(server_frame, text="Stop Server", command=self.stop, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.text_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.text_widget.pack(expand=True, fill=tk.BOTH, pady=5)

        self.client_list_label = ttk.Label(main_frame, text="Connected Clients:")
        self.client_list_label.pack()

        self.client_list = tk.Listbox(main_frame)
        self.client_list.pack(expand=True, fill=tk.BOTH)

    def perform_key_exchange(self, client_socket):
        try:
            private_key, public_key = KeyExchange.generate_key_pair()
            client_public_key_bytes = client_socket.recv(32)
            client_public_key = KeyExchange.deserialize_public_key(client_public_key_bytes)

            # Send server's public key
            client_socket.send(
                public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )

            shared_secret = KeyExchange.generate_shared_secret(private_key, client_public_key)
            print(f"Server shared secret: {shared_secret.hex()}")

            symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
            print("Server key derivation parameters:")
            print(f"Salt: None")
            print(f"Info: handshake data")
            print(f"Shared secret: {shared_secret.hex()}")
            print(f"Server symmetric key: {symmetric_key.hex()}")

            return symmetric_key
        except Exception as e:
            print(f"Key exchange failed: {str(e)}")
            raise

    def start(self):
        self.host = self.host_entry.get()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.update_text_widget(f"Server listening on {self.host}:{self.port}\n")
            print(f"Server listening on {self.host}:{self.port}\n")

            threading.Thread(target=self.run_server, daemon=True).start()
        except Exception as e:
            self.update_text_widget(f"Server failed to start: {str(e)}\n")

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop(self):
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.update_text_widget("Server stopped.\n")

    def run_server(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            client_ip, client_port = client_address

            try:
                symmetric_key = self.perform_key_exchange(client_socket)
                self.clients[client_socket] = {
                    "address": client_address,
                    "symmetric_key": symmetric_key,
                    "room": None  # Initially not in any room
                }

                self.root.after(0, self.update_text_widget, f"Accepted connection from {client_ip}:{client_port}\n")
                print(f"Accepted connection from {client_ip}:{client_port}\n")

                self.root.after(0, self.update_client_list)

                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()
            except Exception as e:
                print(f"Error handling client {client_ip}:{client_port}: {str(e)}")
                client_socket.close()

    def handle_client(self, client_socket):
        client_data = self.clients[client_socket]
        client_address = client_data["address"]
        symmetric_key = client_data["symmetric_key"]
        client_ip, client_port = client_address

        try:
            while True:
                encrypted_data = client_socket.recv(1024)

                if not encrypted_data:
                    self.update_text_widget(f"Client {client_ip}:{client_port} disconnected.\n")
                    print(f"Client {client_ip}:{client_port} disconnected.\n")
                    self.leave_room(client_socket)  # Remove client from room if connected
                    del self.clients[client_socket]
                    self.update_client_list()
                    client_socket.close()
                    break

                try:
                    decoded_data = base64.b64decode(encrypted_data)
                    decrypted_data = AESGCMCipher.decrypt(symmetric_key, decoded_data)

                    if decrypted_data.startswith("/join "):
                        self.join_room(client_socket, decrypted_data[6:].strip())
                    elif decrypted_data.startswith("/leave"):
                        self.leave_room(client_socket)
                    else:
                        self.broadcast(decrypted_data, client_socket)
                except Exception as e:
                    self.update_text_widget(f"Error decrypting message from {client_ip}:{client_port}: {str(e)}\n")
        except Exception as e:
            self.update_text_widget(f"An error occurred with client {client_ip}:{client_port}: {str(e)}\n")
        finally:
            if client_socket in self.clients:
                self.leave_room(client_socket)
                del self.clients[client_socket]
            client_socket.close()

    def join_room(self, client_socket, room_name):
        if room_name not in self.rooms:
            self.rooms[room_name] = []
            self.update_text_widget(f"Room {room_name} created.\n")

        current_room = self.clients[client_socket]["room"]
        if current_room:
            self.rooms[current_room].remove(client_socket)

        self.rooms[room_name].append(client_socket)
        self.clients[client_socket]["room"] = room_name
        self.update_text_widget(f"Client joined room: {room_name}\n")

    def leave_room(self, client_socket):
        current_room = self.clients[client_socket]["room"]
        if current_room and client_socket in self.rooms[current_room]:
            self.rooms[current_room].remove(client_socket)
            self.update_text_widget(f"Client left room: {current_room}\n")
        self.clients[client_socket]["room"] = None

    def broadcast(self, message, sender_socket):
        sender_room = self.clients[sender_socket]["room"]
        if sender_room:
            for client_socket in self.rooms[sender_room]:
                if client_socket != sender_socket:
                    symmetric_key = self.clients[client_socket]["symmetric_key"]
                    encrypted_message = AESGCMCipher.encrypt(symmetric_key, message)
                    client_socket.send(base64.b64encode(encrypted_message))

    def update_text_widget(self, message):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, message)
        self.text_widget.config(state=tk.DISABLED)
        self.text_widget.yview(tk.END)

    def update_client_list(self):
        self.client_list.delete(0, tk.END)
        for client_socket, client_data in self.clients.items():
            client_ip, client_port = client_data["address"]
            self.client_list.insert(tk.END, f"{client_ip}:{client_port}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    server_gui = ServerGUI()
    server_gui.run()
