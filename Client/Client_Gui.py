import tkinter as tk
from tkinter import ttk
import socket
import threading
import pygame

pygame.init()


class ClientGUI:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.connected = False
        self.index = 0
        self.chat_history = []
        self.edited_chat_history = []
        self.client_messages = {}
        self.current_room = None

        self.root = tk.Tk()
        self.root.title("Chat Client")

        self.style = ttk.Style()
        self.style.theme_use("clam")

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

        self.input_entry = ttk.Entry(self.main_frame, state=tk.DISABLED)
        self.input_entry.grid(column=0, row=5, columnspan=2, sticky=(tk.W, tk.E))

        self.send_button = ttk.Button(self.main_frame, text="Send", command=self.send_message,
                                      state=tk.DISABLED)
        self.send_button.grid(column=1, row=6, sticky=tk.E)

    def on_enter(self, e, btn):
        btn['background'] = '#2980b9'

    def on_leave(self, e, btn):
        btn['background'] = '#3498db'

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
        elif message.startswith("/edit"):
            self.client_socket.send(message.encode('utf-8'))
        elif message.startswith("/join"):
            self.message_join(message)
        elif message.startswith("/leave"):
            self.message_leave(message)
        elif message.startswith("/clear"):
            self.clear_screen()
            self.chat_history = []
        else:
            self.message_send(message)
        self.input_entry.delete(0, tk.END)

    def message_send(self, message):
        formatted_message = f"{self.username}: {message}"
        self.client_socket.send(formatted_message.encode('utf-8'))
        self.chat_history.append(formatted_message)
        self.text_widget.insert(tk.END, formatted_message + "\n")

    def message_leave(self, message):
        sound = pygame.mixer.Sound("E:\python\Licenta_MessagingApp\door_close.mp3")
        sound.play()
        self.client_socket.send(message.encode('utf-8'))

    def message_join(self, message):
        self.current_room = message.split()[1]
        self.client_socket.send(message.encode('utf-8'))

    def start_receiving(self):
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(1024).decode('utf-8')
                if not data:
                    self.text_widget.insert(tk.END, "Server closed the connection.\n")
                    break
                self.text_widget.insert(tk.END, data + "\n")
        except Exception as e:
            self.text_widget.insert(tk.END, f"An error occurred: {str(e)}\n")
        finally:
            self.client_socket.close()

    def run(self):
        self.root.mainloop()

    def clear_screen(self):
        self.text_widget.delete(1.0, tk.END)

    def restore_chat_history(self):
        for message in self.chat_history:
            if not message.startswith("/delete "):
                self.text_widget.insert(tk.END, 'User: ' + message + "\n")


if __name__ == "__main__":
    client_gui = ClientGUI()
    client_gui.run()
