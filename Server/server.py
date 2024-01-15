import socket
import threading


class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.chat_history = []  # Store chat history as a list of messages

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Accepted connection from {client_address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            self.clients.append(client_socket)

    def handle_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8')

                if not data:
                    print(f"Client {client_socket.getpeername()} disconnected.")
                    self.clients.remove(client_socket)
                    client_socket.close()
                    break
                elif data.startswith('/edit '):
                    # Handle message editing command
                    self.edit_message(client_socket, data)
                elif data.startswith('/delete '):
                    # Handle message deletion command
                    self.delete_message(client_socket, data)
                else:
                    # Regular message broadcast
                    self.chat_history.append(data)
                    self.broadcast(data, client_socket)
        except Exception as e:
            print(f"An error occurred with client {client_socket.getpeername()}: {str(e)}")

    def broadcast(self, message, sender_socket):
        for client in self.clients:
            if client != sender_socket:
                try:
                    client.send(message.encode('utf-8'))
                except Exception as e:
                    print(f"Failed to send message to client {client.getpeername()}:{str(e)}")

    def edit_message(self, sender_socket, data):
        # Extract the edited message content and message index
        parts = data.split(' ', 2)
        if len(parts) == 3:
            try:
                message_index = int(parts[1])
                new_content = parts[2]
                if 0 <= message_index < len(self.chat_history):
                    # Update the message in chat history
                    self.chat_history[message_index] = new_content
                    self.broadcast(f'Message {message_index} edited: {new_content}', sender_socket)
            except (ValueError, IndexError):
                pass

    def delete_message(self, sender_socket, data):
        # Extract the message index to delete
        parts = data.split(' ', 1)
        if len(parts) == 2:
            try:
                message_index = int(parts[1])
                if 0 <= message_index < len(self.chat_history):
                    # Delete the message from chat history
                    deleted_message = self.chat_history.pop(message_index)
                    self.broadcast(f'Message {message_index} deleted: {deleted_message}', sender_socket)
            except (ValueError, IndexError):
                pass


if __name__ == "__main__":
    server = ChatServer('192.168.100.100', 8080)
    server.start()
