import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import base64
from cryptography.hazmat.primitives import serialization
from TLS.KeyExchange import KeyExchange
from TLS.KeyDerivation import KeyDerivation
from TLS.AES_GCM_CYPHER import AESGCMCipher


class ModernButton(ttk.Button):
    """Custom button with hover effects"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)

    def _on_enter(self, e):
        self['style'] = 'Accent.TButton'

    def _on_leave(self, e):
        self['style'] = 'TButton'


class ClientGUI:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.connected = False
        self.symmetric_key = None
        self.rooms = []

        # Window Setup
        self.root = tk.Tk()
        self.root.title("Secure Chat")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        self.root.configure(bg='#1A1B26')

        # Load custom fonts
        self.load_custom_fonts()

        # Configure modern styling
        self.setup_styles()

        # Create main container
        self.container = ttk.Frame(self.root, style='Main.TFrame', padding="15")
        self.container.pack(expand=True, fill=tk.BOTH)

        # Create sections
        self.create_header_section()
        self.create_main_section()
        self.create_status_bar()

        # Set up bindings
        self.setup_bindings()

    def load_custom_fonts(self):
        # Note: These are system fonts that are commonly available
        self.header_font = ('Segoe UI', 13, 'bold')
        self.normal_font = ('Segoe UI', 11)
        self.message_font = ('Segoe UI', 11)
        self.status_font = ('Segoe UI', 10)

    def setup_styles(self):
        # Modern color palette inspired by Tokyo Night theme
        colors = {
            'bg': '#0F0E17',
            'fg': '#FFFFFF',
            'accent': '#FF8906',
            'accent_hover': '#FFB85C',
            'secondary': '#2E2F3E',
            'tertiary': '#4A4B5E',
            'success': '#6EC867',
            'error': '#E63946',
            'input_bg': '#23233A',
            'selection': '#3E497A'
        }

        style = ttk.Style()
        style.theme_use('clam')

        # Frame styles
        style.configure('Main.TFrame', background=colors['bg'])
        style.configure('Header.TFrame', background=colors['secondary'])
        style.configure('Content.TFrame', background=colors['bg'])

        # Label styles
        style.configure('TLabel',
                        background=colors['bg'],
                        foreground=colors['fg'],
                        font=self.normal_font)

        style.configure('Header.TLabel',
                        background=colors['secondary'],
                        foreground=colors['fg'],
                        font=self.header_font)

        style.configure('Status.TLabel',
                        background=colors['tertiary'],
                        foreground=colors['fg'],
                        font=self.status_font)

        # Button styles
        style.configure('TButton',
                        background=colors['accent'],
                        foreground=colors['fg'],
                        padding=(15, 8),
                        font=self.normal_font)

        style.configure('Accent.TButton',
                        background=colors['accent_hover'],
                        foreground=colors['fg'])

        style.map('TButton',
                  background=[('active', colors['accent_hover'])],
                  foreground=[('active', colors['fg'])])

        # Entry styles
        style.configure('TEntry',
                        fieldbackground=colors['input_bg'],
                        foreground=colors['fg'],
                        padding=10,
                        font=self.normal_font)

        style.map('TEntry',
                  fieldbackground=[('focus', colors['secondary'])])

        # Scrollbar style
        style.configure('TScrollbar',
                        background=colors['tertiary'],
                        troughcolor=colors['bg'],
                        borderwidth=0,
                        arrowcolor=colors['fg'])

        # Text widget configuration dictionary
        text_config = {
            'bg': colors['input_bg'],
            'fg': colors['fg'],
            'selectbackground': colors['selection'],
            'selectforeground': colors['fg'],
            'font': self.message_font,
            'relief': 'flat',
            'padx': 10,
            'pady': 10,
            'borderwidth': 0
        }

        # Configure root window background
        self.root.configure(bg=colors['bg'])

        # Configure Text and Listbox through option database
        self.root.option_add('*Text.font', self.message_font)
        self.root.option_add('*Text.relief', 'flat')
        self.root.option_add('*Text.background', colors['input_bg'])
        self.root.option_add('*Text.foreground', colors['fg'])
        self.root.option_add('*Text.selectBackground', colors['selection'])
        self.root.option_add('*Text.selectForeground', colors['fg'])

        self.root.option_add('*Listbox.font', self.normal_font)
        self.root.option_add('*Listbox.background', colors['input_bg'])
        self.root.option_add('*Listbox.foreground', colors['fg'])
        self.root.option_add('*Listbox.selectBackground', colors['selection'])
        self.root.option_add('*Listbox.selectForeground', colors['fg'])
        self.root.option_add('*Listbox.relief', 'flat')

        return text_config

    def create_header_section(self):
        header = ttk.Frame(self.container, style='Header.TFrame')
        header.pack(fill=tk.X, pady=(0, 15))

        # Add subtle border to header
        separator = ttk.Separator(self.container, orient='horizontal')
        separator.pack(fill=tk.X, pady=(0, 15))

        # Connection settings
        settings_frame = ttk.Frame(header, style='Header.TFrame', padding="10")
        settings_frame.pack(expand=True, fill=tk.X)

        # Left side - Server settings
        server_frame = ttk.Frame(settings_frame, style='Header.TFrame')
        server_frame.pack(side=tk.LEFT, padx=20)

        ttk.Label(server_frame, text="CONNECTION", style='Header.TLabel').pack(anchor=tk.W)

        # IP and Port in same row
        conn_frame = ttk.Frame(server_frame, style='Header.TFrame')
        conn_frame.pack(fill=tk.X, pady=(10, 0))

        ip_frame = ttk.Frame(conn_frame, style='Header.TFrame')
        ip_frame.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(ip_frame, text="IP", style='Header.TLabel').pack(side=tk.LEFT, padx=(0, 8))
        self.ip_entry = ttk.Entry(ip_frame, width=15)
        self.ip_entry.pack(side=tk.LEFT)
        self.ip_entry.insert(0, "127.0.0.1")

        port_frame = ttk.Frame(conn_frame, style='Header.TFrame')
        port_frame.pack(side=tk.LEFT)
        ttk.Label(port_frame, text="PORT", style='Header.TLabel').pack(side=tk.LEFT, padx=(0, 8))
        self.port_entry = ttk.Entry(port_frame, width=7)
        self.port_entry.pack(side=tk.LEFT)
        self.port_entry.insert(0, "8080")

        # Center - Username
        user_frame = ttk.Frame(settings_frame, style='Header.TFrame')
        user_frame.pack(side=tk.LEFT, padx=20)

        ttk.Label(user_frame, text="USERNAME", style='Header.TLabel').pack(anchor=tk.W)
        self.username_entry = ttk.Entry(user_frame, width=20)
        self.username_entry.pack(pady=(10, 0))

        # Right side - Connect button
        button_frame = ttk.Frame(settings_frame, style='Header.TFrame')
        button_frame.pack(side=tk.RIGHT, padx=20)

        self.connect_button = ModernButton(
            button_frame,
            text="Connect",
            command=self.connect,
            style='Accent.TButton',
            padding=(30, 12)
        )
        self.connect_button.pack(pady=(25, 0))

    def create_main_section(self):
        main_content = ttk.PanedWindow(self.container, orient=tk.HORIZONTAL)
        main_content.pack(expand=True, fill=tk.BOTH)

        # Chat section (left)
        chat_frame = ttk.Frame(main_content, style='Content.TFrame')
        main_content.add(chat_frame, weight=7)

        # Chat container
        chat_container = ttk.Frame(chat_frame, style='Content.TFrame')
        chat_container.pack(expand=True, fill=tk.BOTH, padx=15)

        ttk.Label(chat_container, text="MESSAGES", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

        # Chat log with custom styling
        text_config = self.setup_styles()
        self.chat_log = tk.Text(
            chat_container,
            wrap=tk.WORD,
            state=tk.DISABLED,
            **text_config
        )
        # Set insert cursor color after creation
        self.chat_log.config(insertbackground=text_config['fg'])
        self.chat_log.pack(expand=True, fill=tk.BOTH)

        # Modern scrollbar
        chat_scrollbar = ttk.Scrollbar(chat_container, orient=tk.VERTICAL, command=self.chat_log.yview)
        chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_log.configure(yscrollcommand=chat_scrollbar.set)

        # Message input area
        input_frame = ttk.Frame(chat_frame, style='Content.TFrame', padding="15")
        input_frame.pack(fill=tk.X)

        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        self.message_entry.config(state=tk.DISABLED)

        self.send_button = ModernButton(
            input_frame,
            text="Send",
            command=self.send_message,
            state=tk.DISABLED,
            padding=(20, 10)
        )
        self.send_button.pack(side=tk.RIGHT)

        # Room section (right)
        room_frame = ttk.Frame(main_content, style='Content.TFrame')
        main_content.add(room_frame, weight=3)

        room_container = ttk.Frame(room_frame, style='Content.TFrame', padding="15")
        room_container.pack(expand=True, fill=tk.BOTH)

        ttk.Label(room_container, text="ROOMS", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

        # Room list
        self.room_list = tk.Listbox(
            room_container,
            selectmode=tk.SINGLE,
            **{k: v for k, v in self.setup_styles().items() if k != 'padx' and k != 'pady'}
        )
        self.room_list.pack(expand=True, fill=tk.BOTH, pady=(0, 15))

        # Room controls
        self.room_entry = ttk.Entry(room_container)
        self.room_entry.pack(fill=tk.X, pady=(0, 10))
        self.room_entry.insert(0, "Enter room name...")
        self.room_entry.bind('<FocusIn>', lambda e: self.on_entry_click(e, "Enter room name..."))
        self.room_entry.bind('<FocusOut>', lambda e: self.on_focus_out(e, "Enter room name..."))

        button_frame = ttk.Frame(room_container, style='Content.TFrame')
        button_frame.pack(fill=tk.X, pady=(0, 5))

        self.join_room_button = ModernButton(button_frame, text="Join Room", command=self.join_room)
        self.join_room_button.pack(fill=tk.X, pady=(0, 5))

        self.leave_room_button = ModernButton(button_frame, text="Leave Room", command=self.leave_room)
        self.leave_room_button.pack(fill=tk.X)

    def create_status_bar(self):
        status_frame = ttk.Frame(self.container, style='Header.TFrame')
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(15, 0))

        self.status_bar = ttk.Label(
            status_frame,
            text="Not connected",
            style='Status.TLabel',
            padding=(10, 8)
        )
        self.status_bar.pack(fill=tk.X)
    def setup_bindings(self):
        # Bind Enter key to send message
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        # Bind Enter key to join room when room entry is focused
        self.room_entry.bind('<Return>', lambda e: self.join_room())

        # Bind double-click to leave room
        self.room_list.bind('<Double-Button-1>', lambda e: self.leave_room())

    def on_entry_click(self, event, default_text):
        """Clear placeholder text on entry field focus"""
        if event.widget.get() == default_text:
            event.widget.delete(0, tk.END)
            event.widget.config(foreground='#CDD6F4')

    def on_focus_out(self, event, default_text):
        """Restore placeholder text if entry is empty"""
        if event.widget.get() == '':
            event.widget.insert(0, default_text)
            event.widget.config(foreground='#6C7086')

    def update_status(self, message, status_type='info'):
        """Update status bar with message and appropriate styling"""
        self.status_bar['text'] = message
        if status_type == 'error':
            self.status_bar['foreground'] = '#F38BA8'
        elif status_type == 'success':
            self.status_bar['foreground'] = '#A6E3A1'
        else:
            self.status_bar['foreground'] = '#CDD6F4'

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
                self.ip_entry.config(state=tk.DISABLED)
                self.port_entry.config(state=tk.DISABLED)
                self.connect_button.config(state=tk.DISABLED)
                self.message_entry.config(state=tk.NORMAL)
                self.send_button.config(state=tk.NORMAL)
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
                self.chat_log.config(state=tk.NORMAL)
                self.chat_log.insert(tk.END, "Join a room first using the Room Management panel.\n")
                self.chat_log.config(state=tk.DISABLED)
                return

            formatted_message = f"{self.username}: {message}"
            self.chat_log.config(state=tk.NORMAL)
            self.chat_log.insert(tk.END, formatted_message + "\n")
            self.chat_log.see(tk.END)  # Auto-scroll to bottom
            self.chat_log.config(state=tk.DISABLED)

            self.client_socket.send(self.encrypt_message(formatted_message))
            self.message_entry.delete(0, tk.END)

    def join_room(self):
        room_name = self.room_entry.get().strip()
        if room_name == "Enter room name...":
            self.update_status("Please enter a valid room name", 'error')
            return

        if room_name and room_name not in self.rooms:
            try:
                self.rooms.append(room_name)
                self.room_list.insert(tk.END, room_name)
                self.client_socket.send(self.encrypt_message(f"/join {room_name}"))

                self.chat_log.config(state=tk.NORMAL)
                self.chat_log.insert(tk.END, f"→ Joined room: {room_name}\n")
                self.chat_log.see(tk.END)
                self.chat_log.config(state=tk.DISABLED)

                self.room_entry.delete(0, tk.END)
                self.room_entry.insert(0, "Enter room name...")
                self.room_entry.config(foreground='#6C7086')

                self.update_status(f"Successfully joined room: {room_name}", 'success')
            except Exception as e:
                self.update_status(f"Failed to join room: {str(e)}", 'error')
                self.rooms.remove(room_name)
                self.room_list.delete(tk.END)

    def leave_room(self):
        selection = self.room_list.curselection()
        if not selection:
            self.update_status("Please select a room to leave", 'error')
            return

        selected_room = self.room_list.get(selection[0])
        try:
            self.rooms.remove(selected_room)
            self.room_list.delete(selection[0])
            self.client_socket.send(self.encrypt_message(f"/leave {selected_room}"))

            self.chat_log.config(state=tk.NORMAL)
            self.chat_log.insert(tk.END, f"← Left room: {selected_room}\n")
            self.chat_log.see(tk.END)
            self.chat_log.config(state=tk.DISABLED)

            self.update_status(f"Successfully left room: {selected_room}", 'success')
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

                self.chat_log.config(state=tk.NORMAL)
                self.chat_log.insert(tk.END, decrypted_message + "\n")
                self.chat_log.see(tk.END)
                self.chat_log.config(state=tk.DISABLED)
        except ConnectionError as e:
            self.handle_disconnect(str(e))
        except Exception as e:
            self.handle_disconnect(f"Error: {str(e)}")

    def handle_disconnect(self, error_message):
        """Handle disconnection gracefully"""
        self.connected = False
        self.chat_log.config(state=tk.NORMAL)
        self.chat_log.insert(tk.END, f"❌ {error_message}\n")
        self.chat_log.see(tk.END)
        self.chat_log.config(state=tk.DISABLED)

        # Reset UI elements
        self.username_entry.config(state=tk.NORMAL)
        self.ip_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        self.connect_button.config(state=tk.NORMAL)
        self.message_entry.config(state=tk.DISABLED)
        self.send_button.config(state=tk.DISABLED)

        # Clear rooms
        self.rooms.clear()
        self.room_list.delete(0, tk.END)

        self.update_status("Disconnected from server", 'error')

        try:
            self.client_socket.close()
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            pass

    def perform_key_exchange(self):
        """Perform secure key exchange with server"""
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
        """Encrypt message using established symmetric key"""
        try:
            encrypted_message = AESGCMCipher.encrypt(self.symmetric_key, message)
            return base64.b64encode(encrypted_message)
        except Exception as e:
            self.update_status(f"Encryption failed: {str(e)}", 'error')
            raise

    def run(self):
        """Start the application"""
        # Center window on screen
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