import socket
import threading


class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None

    def get_username(self):
        return self.username

    def connect(self):
        try:
            # Connect to the server
            self.client_socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            # Prompt the user to enter their username
            self.username = input("Enter your username: ")

            # Start receiving and sending messages
            self.start_receiving()
            self.start_sending()
        except Exception as e:
            print(f"Connection error: {str(e)}")

    def start_receiving(self):
        # Start a thread for receiving messages from the server
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

    def receive_messages(self):
        try:
            while True:
                # Receive and display messages from the server
                data = self.client_socket.recv(1024).decode('utf-8')
                if not data:
                    print("Server closed the connection.")
                    break
                print(data)
        except Exception as e:
            print(f"An error occurred: {str(e)}")
        finally:
            # Close the client socket when done
            self.client_socket.close()

    def start_sending(self):
        try:
            while True:
                # Get user input for sending messages
                message = input()

                # Check if the user wants to exit
                if message.lower() == "/exit":
                    self.client_socket.send("/exit".encode('utf-8'))
                    break
                # Check if the user wants to delete a message
                elif message.startswith("/delete"):
                    self.client_socket.send(message.encode('utf-8'))
                # Check if the user wants to edit a message
                elif message.startswith("/edit"):
                    self.client_socket.send(message.encode('utf-8'))
                else:
                    # Send the message to the server with the username
                    self.client_socket.send(f"{self.username}: {message}".encode('utf-8'))
        except Exception as e:
            print(f"An error occurred: {str(e)}")
        finally:
            # Close the client socket when done
            self.client_socket.close()


if __name__ == "__main__":
    client = ChatClient('192.168.100.100', 8080)
    client.connect()
