import tkinter as tk
from tkinter import ttk
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
        self.root.title("Chat Client")

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("Sandy.TFrame", background="sandy brown")

        self.main_frame = ttk.Frame(self.root, padding=10, style="Sandy.TFrame")
        self.main_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.server_ip_label = ttk.Label(self.main_frame, font='Verdana 15 underline', background='white',
                                         text="Enter Server IP :")
        self.server_ip_label.grid(column=0, row=0, sticky=tk.W)

        self.ip_entry = ttk.Entry(self.main_frame)
        self.ip_entry.grid(column=1, row=0, sticky=(tk.W, tk.E))

        self.server_port_label = ttk.Label(self.main_frame, font='Verdana 15 underline', background='white',
                                           text="Enter Server Port :")
        self.server_port_label.grid(column=0, row=1, sticky=tk.W)

        self.port_entry = ttk.Entry(self.main_frame)
        self.port_entry.grid(column=1, row=1, sticky=(tk.W, tk.E))

        self.username_label = ttk.Label(self.main_frame, font='Verdana 15 underline', background='white',
                                        text="Enter Username:")
        self.username_label.grid(column=0, row=2, sticky=tk.W)

        self.username_entry = ttk.Entry(self.main_frame)
        self.username_entry.grid(column=1, row=2, sticky=(tk.W, tk.E))

        self.connect_button = ttk.Button(self.main_frame, text="Connect", command=self.connect)
        self.connect_button.grid(column=1, row=3, sticky=tk.E)

        self.text_widget = tk.Text(self.main_frame)
        self.text_widget.grid(column=0, row=4, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.input_entry = ttk.Entry(self.main_frame, state=tk.DISABLED)
        self.input_entry.grid(column=0, row=5, columnspan=2, sticky=(tk.W, tk.E))

        self.send_button = ttk.Button(self.main_frame, text="Send", command=self.send_message, state=tk.DISABLED)
        self.send_button.grid(column=1, row=6, sticky=tk.E)

    def perform_key_exchange(self):
        self.private_key, self.public_key = KeyExchange.generate_key_pair()

        # Send public key to server in raw format
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.client_socket.send(public_key_bytes)

        # Receive server's public key
        server_public_key_bytes = self.client_socket.recv(32)
        server_public_key = KeyExchange.deserialize_public_key(server_public_key_bytes)

        # Generate shared secret and derive symmetric key
        shared_secret = KeyExchange.generate_shared_secret(self.private_key, server_public_key)
        print(f"Client shared secret: {shared_secret.hex()}")
        self.symmetric_key = KeyDerivation.derive_symmetric_key(shared_secret)
        print(f"Client symmetric key: {self.symmetric_key.hex()}")

    def connect(self):
        if not self.connected:
            try:
                server_ip = self.get_server_ip()
                server_port = int(self.get_server_port())
                self.client_socket.connect((server_ip, server_port))

                self.perform_key_exchange()

                self.text_widget.insert(tk.END, f"Connected to {server_ip}:{server_port}\n")
                self.username = self.username_entry.get()
                self.username_entry.config(state=tk.DISABLED)
                self.connect_button.config(state=tk.DISABLED)
                self.input_entry.config(state=tk.NORMAL)
                self.send_button.config(state=tk.NORMAL)
                self.connected = True
                self.start_receiving()

            except Exception as e:
                self.text_widget.insert(tk.END, f"Connection error: {str(e)}\n")

    def send_message(self):
        message = self.input_entry.get()
        if message.startswith("/join "):
            room_name = message.split(" ", 1)[1].strip()
            if room_name not in self.rooms:
                self.rooms.append(room_name)
                self.text_widget.insert(tk.END, f"Joined room: {room_name}\n")
            self.client_socket.send(self.encrypt_message(message))
        elif message.startswith("/leave "):
            room_name = message.split(" ", 1)[1].strip()
            if room_name in self.rooms:
                self.rooms.remove(room_name)
                self.text_widget.insert(tk.END, f"Left room: {room_name}\n")
            self.client_socket.send(self.encrypt_message(message))
        elif message:
            if not self.rooms:
                self.text_widget.insert(tk.END, "Join a room first using /join [room_name]\n")
                return
            formatted_message = f"{self.username}: {message}"
            self.text_widget.insert(tk.END, formatted_message + "\n")
            self.client_socket.send(self.encrypt_message(formatted_message))
        self.input_entry.delete(0, tk.END)

    def encrypt_message(self, message):
        encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, message)
        print(f"Client encrypted message (base64): {base64.b64encode(encrypted_message).decode()}")
        return base64.b64encode(encrypted_message)

    def receive_messages(self):
        try:
            while True:
                encrypted_data = self.client_socket.recv(1024)
                if not encrypted_data:
                    self.text_widget.insert(tk.END, "Server closed the connection.\n")
                    break

                try:
                    decoded_data = base64.b64decode(encrypted_data)
                    decrypted_message = AESGCMCipher.decrypt(self.symmetric_key, decoded_data)
                    self.text_widget.insert(tk.END, decrypted_message + "\n")
                except Exception as e:
                    self.text_widget.insert(tk.END, f"Decryption error: {str(e)}\n")

        except Exception as e:
            self.text_widget.insert(tk.END, f"Error occurred: {str(e)}\n")
        finally:
            self.client_socket.close()

    def start_receiving(self):
        thread = threading.Thread(target=self.receive_messages, daemon=True)
        thread.start()

    def get_server_ip(self):
        return self.ip_entry.get()

    def get_server_port(self):
        return self.port_entry.get()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    client_gui = ClientGUI()
    client_gui.run()
