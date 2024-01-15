import base64
import tkinter as tk
from tkinter import ttk
import socket
import threading
import pygame
from cryptography.fernet import Fernet

pygame.init()
sound = pygame.mixer.Sound("E:\python\Licenta_MessagingApp\intrare.mp3")
sound.play()


class ClientGUI:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.connected = False  # Track if the user is connected
        self.index = 0
        self.chat_history = []
        self.edited_chat_history = []
        self.client_messages = {}
        self.room_keys = {}  # Dictionary to store keys for each room
        self.current_room = None

        self.root = tk.Tk()
        self.root.title("Chat Client")

        self.style = ttk.Style()
        self.style.theme_use("clam")  # Choose a ttk theme (you can change "clam" to other themes)

        # Create a custom style for the main frame with a sandy background color
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

        self.input_entry = ttk.Entry(self.main_frame, state=tk.DISABLED)  # Disabled initially
        self.input_entry.grid(column=0, row=5, columnspan=2, sticky=(tk.W, tk.E))

        self.send_button = ttk.Button(self.main_frame, text="Send", command=self.send_message,
                                      state=tk.DISABLED)  # Disabled initially
        self.send_button.grid(column=1, row=6, sticky=tk.E)

    def on_enter(self, e, btn):
        btn['background'] = '#2980b9'  # Lighter blue on hover

    def on_leave(self, e, btn):
        btn['background'] = '#3498db'  # Original blue

    def receive_key(self, message):
        try:
            parts = message.split(':')
            room_name = parts[1]
            # Remove "b'" at the beginning and "'" at the end
            key = parts[2][2:-1]
            self.store_room_key(room_name, key)
        except IndexError:
            print("Error parsing the key message")

    def store_room_key(self, room_name, key):
        self.room_keys[room_name] = key
        # print(f"Key for room '{room_name}' stored: {key}")

    def decrypt_message(self, encrypted_message, room_name):
        key = self.room_keys[room_name]
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message)
        return decrypted_message

    def encrypt_message(self, message, room_name):
        # Ensure the message is a byte string
        if isinstance(message, str):
            message = message.encode()

        # Retrieve the key for the given room
        key = self.room_keys[room_name]

        # Initialize the Fernet cipher with the key
        fernet = Fernet(key)

        # Encrypt the message
        encrypted_message = fernet.encrypt(message)

        return encrypted_message


    def get_username(self):
        return self.username

    def get_server_ip(self):
        return self.ip_entry.get()

    def get_server_port(self):
        return self.port_entry.get()

    def connect(self):
        if not self.connected:
            try:
                server_ip = self.get_server_ip()
                server_port = int(self.get_server_port())
                self.client_socket.connect((server_ip, server_port))
                self.text_widget.insert(tk.END, f"Connected to {server_ip}:{server_port}\n")
                self.username = self.username_entry.get()
                self.username_entry.config(state=tk.DISABLED)
                self.connect_button.config(state=tk.DISABLED)
                self.input_entry.config(state=tk.NORMAL)
                self.send_button.config(state=tk.NORMAL)
                self.connected = True
                self.start_receiving()
                self.client_socket.send(
                    "/join Private (To join/leave a room write /join/leave [room_name]".encode('utf-8'))
            except Exception as e:
                self.text_widget.insert(tk.END, f"Connection error: {str(e)}\n")

    def send_message(self):
        message = self.input_entry.get()
        self.index += 1
        if message.lower() == "/exit":
            self.client_socket.send("/exit".encode('utf-8'))
            self.root.quit()
        elif message.startswith("/delete"):
            self.client_socket.send(message.encode('utf-8'))
            parts = message.split(' ', 2)
            message_index = int(parts[1])
            self.chat_history.pop(message_index)
            self.clear_screen()
            self.restore_chat_history()

        elif message.startswith("/edit"):
            self.client_socket.send(message.encode('utf-8'))
        elif message.startswith("/join"):
            self.current_room = message.split()[1]
            self.client_socket.send(message.encode('utf-8'))
            sound = pygame.mixer.Sound("E:\python\Licenta_MessagingApp\door_open.mp3")
            sound.play()
        elif message.startswith("/leave"):
            sound = pygame.mixer.Sound("E:\python\Licenta_MessagingApp\door_close.mp3")
            sound.play()
            self.client_socket.send(message.encode('utf-8'))
        elif message.startswith("/clear"):
            self.clear_screen()
            self.chat_history = []
        else:
            # Format the message with username
            formatted_message = f"{self.username}: {message}"

            # Encrypt the formatted message
            encrypted_message = self.encrypt_message(formatted_message, self.current_room)

            # Prepend the identifier for encrypted messages
            message_to_send = f"ENC_MSG:{encrypted_message}"
            self.client_socket.send(message_to_send.encode('utf-8'))

            # Append to chat history and update text widget
            self.chat_history.append(formatted_message)
            self.text_widget.insert(tk.END, formatted_message + "\n")
        self.input_entry.delete(0, tk.END)

    def start_receiving(self):
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(1024).decode('utf-8')
                if data.startswith("KEY_MSG"):
                    self.receive_key(data)
                elif data.startswith("ENC_MSG"):  # Handle encrypted messages
                    # Extract the encrypted part of the message
                    # Remove "ENC_MSG:" from the beginning
                    # print("Mesajul primit=",data)
                    encrypted_message = data.split(":", 1)[1]
                    # print("Mesaj fara ENC_MSG=",encrypted_message)
                    mesaj = encrypted_message[2:-1]
                    # print("Mesaj dupa parsare=",mesaj)
                    # Decrypt the message
                    decrypted_message = self.decrypt_message(mesaj, self.current_room)

                    # Decode the decrypted message to a string
                    decrypted_message = decrypted_message.decode()

                    # Display the decrypted message
                    self.text_widget.insert(tk.END, decrypted_message + "\n")
                else:
                    if not data:
                        self.text_widget.insert(tk.END, "Server closed the connection.\n")
                        break
                    sound = pygame.mixer.Sound("E:\python\Licenta_MessagingApp\steam_sound.mp3")
                    sound.play()
                    self.text_widget.insert(tk.END, data + "\n")
        except Exception as e:
            self.text_widget.insert(tk.END, f"An error occurred: {str(e)}\n")
        finally:
            self.client_socket.close()

    def run(self):
        self.root.mainloop()

    def clear_screen(self):
        self.text_widget = tk.Text(self.main_frame)
        self.text_widget.grid(column=0, row=3, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

    def restore_chat_history(self):
        for message in self.chat_history:
            if not message.startswith("/delete "):
                self.text_widget.insert(tk.END, 'User: ' + message + "\n")


if __name__ == "__main__":
    client_gui = ClientGUI()
    client_gui.run()
