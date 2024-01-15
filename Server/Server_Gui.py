import tkinter as tk
import socket
import threading
from cryptography.fernet import Fernet
from tkinter import ttk, scrolledtext


class ServerGUI:
    def __init__(self):
        self.host = None
        self.port = 8080
        self.server_socket = None
        self.clients = {}
        self.rooms = {}
        self.chat_history = []
        self.keys = {}

        self.root = tk.Tk()
        self.root.title("Chat Server")
        self.root.geometry("600x400")  # Set initial size of the window

        # Styles
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#333")
        self.style.configure("TLabel", background="#333", foreground="white")
        self.style.configure("TButton", background="#333", foreground="white")

        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Server Configuration Frame
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

        # Text Widget with Scrollbar
        self.text_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.text_widget.pack(expand=True, fill=tk.BOTH, pady=5)

        # Clients List
        self.client_list_label = ttk.Label(main_frame, text="Connected Clients:")
        self.client_list_label.pack()

        self.client_list = tk.Listbox(main_frame)
        self.client_list.pack(expand=True, fill=tk.BOTH)

    def start(self):
        self.host = self.host_entry.get()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.text_widget.insert(tk.END, f"Server listening on {self.host}:{self.port}\n")
            print(f"Server listening on {self.host}:{self.port}\n")

            # Start server listening loop in a separate thread
            threading.Thread(target=self.run_server, daemon=True).start()
        except Exception as e:
            self.text_widget.insert(tk.END, f"Server failed to start: {str(e)}\n")

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop(self):
        # Implement the logic to stop the server here
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

        # Update the GUI
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.update_text_widget("Server stopped.\n")
    def run_server(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            client_ip, client_port = client_address

            # Use after to safely update the GUI from another thread
            self.root.after(0, self.update_text_widget, f"Accepted connection from {client_ip}:{client_port}\n")
            print(f"Accepted connection from {client_ip}:{client_port}\n")
            self.clients[client_socket] = client_address

            # Update client list in a thread-safe way
            self.root.after(0, self.update_client_list)

            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_ip, client_port))
            client_thread.start()

    def update_text_widget(self, message):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, message)
        self.text_widget.config(state=tk.DISABLED)
        self.text_widget.yview(tk.END)

    def generate_symmetric_key(self):
        key = Fernet.generate_key()
        self.update_text_widget(f"Generated Key: {key}\n")  # Update to insert in text widget
        return key

    def handle_client(self, client_socket, client_ip, client_port):
        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8')

                if not data:
                    self.text_widget.insert(tk.END, f"Client {client_ip}:{client_port} disconnected.\n")
                    print(f"Client {client_ip}:{client_port} disconnected.\n")
                    del self.clients[client_socket]
                    self.update_client_list()
                    client_socket.close()
                    break
                elif data.startswith('/edit '):
                    self.edit_message(client_socket, data)
                elif data.startswith('/delete '):
                    self.delete_message(client_socket, data)
                elif data.startswith('/join '):
                    self.join_room(client_socket, data)
                elif data.startswith('/leave '):
                    self.leave_room(client_socket, data)
                else:
                    self.chat_history.append(data)
                    self.broadcast(data, client_socket)
        except Exception as e:
            self.text_widget.insert(tk.END, f"An error occurred with client {client_ip}:{client_port}: {str(e)}\n")

    def update_client_list(self):
        self.client_list.delete(0, tk.END)
        for client_socket, client_address in self.clients.items():
            client_ip, client_port = client_address
            self.client_list.insert(tk.END, f"{client_ip}:{client_port}")

    def broadcast(self, message, sender_socket):
        sender_room = None
        print("MESAJUL CRIPTAT=",message)
        # Find the room of the sender
        for room, clients in self.rooms.items():
            if sender_socket in clients:
                sender_room = room
                break

        for room, clients in self.rooms.items():
            if room == sender_room:
                continue  # Skip broadcasting to the sender's room

            for client_socket in clients:
                if client_socket != sender_socket:  # Skip sending the message back to the sender

                    # Check if the sender is still in the room before broadcasting
                    if sender_socket in self.rooms[room]:
                        try:
                            client_socket.send(message.encode('utf-8'))
                        except Exception as e:
                            client_address = self.clients[client_socket]
                            client_ip, client_port = client_address
                            self.text_widget.insert(tk.END,
                                                    f"Failed to send message to {client_ip}:{client_port}: {str(e)}\n")

    def edit_message(self, sender_socket, data):
        parts = data.split(' ', 2)
        if len(parts) == 3:

            try:
                message_index = int(parts[1])
                new_content = parts[2]
                if 0 <= message_index < len(self.chat_history):
                    self.chat_history[message_index] = new_content
                    self.broadcast(f'Message edited: {new_content}', sender_socket)
            except (ValueError, IndexError):
                pass

    def delete_message(self, sender_socket, data):
        parts = data.split(' ', 1)
        if len(parts) == 2:
            try:
                message_index = int(parts[1])
                if 0 <= message_index < len(self.chat_history):
                    deleted_message = self.chat_history.pop(message_index)
                    self.broadcast(f'Message deleted: {deleted_message}', sender_socket)
            except (ValueError, IndexError):
                pass

    def join_room(self, client_socket, data):
        parts = data.split(' ', 1)
        if len(parts) == 2:
            room_name = parts[1].strip()

            if room_name not in self.rooms:
                self.rooms[room_name] = []
                self.keys[room_name] = self.generate_symmetric_key()
                self.update_text_widget(f'Room {room_name} created\n')  # Update to insert in text widget

            self.rooms[room_name].append(client_socket)

            client_socket.send(f'Joined room: {room_name}'.encode('utf-8'))
            # Send the symmetric key to the client
            key_message = f'KEY_MSG:{room_name}:{self.keys[room_name]}'
            client_socket.send(key_message.encode('utf-8'))

    def leave_room(self, client_socket, data):
        parts = data.split(' ', 1)
        if len(parts) == 2:
            room_name = parts[1].strip()

            if room_name in self.rooms:
                if client_socket in self.rooms[room_name]:
                    self.rooms[room_name].remove(client_socket)
                    client_socket.send(f'Left room: {room_name}'.encode('utf-8'))
                else:
                    client_socket.send(f'You are not in room: {room_name}'.encode('utf-8'))
            else:
                client_socket.send(f'Room {room_name} does not exist.'.encode('utf-8'))

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    server_gui = ServerGUI()
    server_gui.run()
