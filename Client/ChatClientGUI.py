import sys
import tkinter

import customtkinter as ctk
from tkinter import messagebox
import threading

from Client.ChatClient import ChatClient
from Client.LoginPopup import LoginPopup
from Client.RoomPopup import RoomPopup



class ChatGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.withdraw()  # Hide main window initially


        # Create login popup
        login = LoginPopup(self.root)
        username = login.get_username()

        if username:
            self.chat_client = ChatClient(message_callback=self.handle_incoming_message)
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
            self.setup_colors()
            self.setup_gui()

            # Pre-fill and connect
            self.username_entry.insert(0, username)
            self.root.after(100, self.auto_connect)  # Connect after GUI is shown
            self.root.deiconify()  # Show main window
        else:
            self.root.destroy()  # Exit if no username provided

    def auto_connect(self):
        """Automatically connect with the pre-filled username"""
        self.connect()

    def setup_colors(self):
        self.colors = {
            'primary': '#1F4690',  # Deep blue - conveys trust and reliability, suitable for CTAs
            'primary_hover': '#1E88E5',  # Medium blue - elegant and eye-catching hover state
            'secondary': '#0077B6',  # Muted teal - secondary actions, professional and calming
            'accent': '#5A189A',  # Rich purple - adds depth and a sense of premium quality for special elements
            'success': '#2E7D32',  # Dark green - sophisticated green for success states
            'error': '#B00020',  # Deep red - serious and clear error indication
            'warning': '#FF8C00',  # Warm amber - attention-grabbing but not overly aggressive
            'surface': '#1C1C1E',  # Charcoal black - main background, professional and minimal
            'surface_dark': '#121212',  # Deep black - darker secondary background, suitable for contrast
            'text': '#F5F5F7',  # Light gray - softer white for primary text, reduces eye strain
            'text_secondary': '#C5C6C7',  # Medium gray - secondary text for subtle emphasis

            # New additions for more depth
            'surface_raised': '#2C2C2E',  # Slightly lighter than surface for elevated components
            'border': '#3C3C3F',  # Dark gray - subtle borders for definition without high contrast
            'border_light': '#55575A',  # Mid gray - highlighted borders, more visible but not stark
            'input_background': '#262628',  # Dark gray - input field background, makes inputs stand out slightly
            'badge_background': 'rgba(31, 70, 144, 0.1)',  # Transparent blue - subtle, professional badge background
            'shadow': '0px 4px 8px rgba(0, 0, 0, 0.15)'  # Slightly deeper shadow for a more refined elevation
        }

    def setup_gui(self):
        self.root = ctk.CTk()
        self.root.title("Secure Chat")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        self.root.iconbitmap("../assets/icon.ico")



        if sys.platform.startswith('win'):
            self.root.wm_attributes('-transparentcolor', 'white')
            self.root.attributes('-alpha', 0.4)  # Slight transparency

        # Instead of overrideredirect, let's use these attributes
        self.root.attributes('-alpha', 1.0)  # Set transparency
        self.root.wm_attributes('-topmost', False)  # Don't keep on top

        # Create custom title bar

        # Main container without border
        self.container = ctk.CTkFrame(
            self.root,
            fg_color=self.colors['surface_dark'],
            corner_radius=0,
            border_width=0
        )
        self.container.pack(expand=True, fill='both')

        # Add taskbar icon support
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit)
        self.root.update_idletasks()

        self.create_header_section()
        self.create_main_section()
        self.create_status_bar()
        self.setup_bindings()
        self.setup_animations()

    def minimize_window(self):
        self.root.wm_withdraw()
        self.root.wm_state('iconic')

    def create_title_bar(self):
        title_bar = ctk.CTkFrame(
            self.root,
            fg_color=self.colors['surface'],
            height=40,
            corner_radius=0
        )
        title_bar.pack(fill='x', side='top')
        title_bar.pack_propagate(False)

        # Title
        title_label = ctk.CTkLabel(
            title_bar,
            text="Secure Chat",
            font=("Segoe UI", 12, "bold"),
            text_color=self.colors['text']
        )
        title_label.pack(side='left', padx=20)

        # Window controls
        controls_frame = ctk.CTkFrame(title_bar, fg_color="transparent")
        controls_frame.pack(side='right', padx=10)

        minimize_btn = ctk.CTkButton(
            controls_frame,
            text="─",
            width=40,
            height=25,
            command=self.minimize_window,  # Use our custom minimize function
            fg_color="transparent",
            hover_color=self.colors['surface_dark'],
            corner_radius=0
        )
        minimize_btn.pack(side='left', padx=2)

        close_btn = ctk.CTkButton(
            controls_frame,
            text="✕",
            width=40,
            height=25,
            command=self.root.quit,
            fg_color="transparent",
            hover_color=self.colors['error'],
            corner_radius=0
        )
        close_btn.pack(side='left', padx=2)

        # Make window draggable
        title_bar.bind('<Button-1>', self.start_move)
        title_bar.bind('<B1-Motion>', self.on_move)

    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def on_move(self, event):
        deltax = event.x - self.x
        deltay = event.y - self.y
        x = self.root.winfo_x() + deltax
        y = self.root.winfo_y() + deltay
        self.root.geometry(f"+{x}+{y}")

    def setup_animations(self):
        def pulse_connect_button():
            if not self.chat_client.connected:
                self.connect_button.configure(fg_color=self.colors['primary_hover'])
                self.root.after(700, lambda: self.connect_button.configure(fg_color=self.colors['primary']))
                self.root.after(1400, pulse_connect_button)

        pulse_connect_button()

    def setup_bindings(self):
        self.message_entry.bind('<Return>', lambda e: self.send_message())

    def create_header_section(self):
        header = ctk.CTkFrame(
            self.container,
            fg_color="transparent",
            height=100
        )
        header.pack(fill='x', pady=(10, 20))

        # Connection settings
        settings_frame = ctk.CTkFrame(
            header,
            fg_color=self.colors['surface'],
            corner_radius=15,
            border_width=1,
            border_color=self.colors['primary']
        )
        settings_frame.pack(expand=True, fill='x', padx=20)

        # Server settings
        server_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        server_frame.pack(side='left', padx=20, pady=15)

        # IP input
        ip_frame = ctk.CTkFrame(server_frame, fg_color="transparent")
        ip_frame.pack(side='left', padx=(0, 20))
        ctk.CTkLabel(
            ip_frame,
            text="🌐 SERVER IP",
            font=("Segoe UI", 12, "bold"),
            text_color=self.colors['text']
        ).pack()
        self.ip_entry = ctk.CTkEntry(
            ip_frame,
            width=150,
            height=35,
            placeholder_text="Enter IP address",
            border_color=self.colors['primary'],
            fg_color=self.colors['surface_dark']
        )
        self.ip_entry.pack(pady=(5, 0))
        self.ip_entry.insert(0, "127.0.0.1")

        # Port input
        port_frame = ctk.CTkFrame(server_frame, fg_color="transparent")
        port_frame.pack(side='left')
        ctk.CTkLabel(
            port_frame,
            text="🔌 PORT",
            font=("Segoe UI", 12, "bold"),
            text_color=self.colors['text']
        ).pack()
        self.port_entry = ctk.CTkEntry(
            port_frame,
            width=100,
            height=35,
            placeholder_text="Port",
            border_color=self.colors['primary'],
            fg_color=self.colors['surface_dark']
        )
        self.port_entry.pack(pady=(5, 0))
        self.port_entry.insert(0, "8080")

        # Username section
        username_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        username_frame.pack(side='left', padx=20)
        ctk.CTkLabel(
            username_frame,
            text="👤 USERNAME",
            font=("Segoe UI", 12, "bold"),
            text_color=self.colors['text']
        ).pack()
        self.username_entry = ctk.CTkEntry(
            username_frame,
            width=200,
            height=35,
            placeholder_text="Enter username",
            border_color=self.colors['primary'],
            fg_color=self.colors['surface_dark']
        )
        self.username_entry.pack(pady=(5, 0))

        # Connect button
        self.connect_button = ctk.CTkButton(
            settings_frame,
            text="CONNECT",
            font=("Segoe UI", 13, "bold"),
            height=35,
            width=150,
            command=self.connect,
            corner_radius=10,
            fg_color=self.colors['primary'],
            hover_color=self.colors['primary_hover']
        )
        self.connect_button.pack(side='right', padx=20)

    def create_main_section(self):
        main_content = ctk.CTkFrame(
            self.container,
            fg_color="transparent"
        )
        main_content.pack(expand=True, fill='both', padx=10, pady=10)

        # Chat section
        chat_frame = ctk.CTkFrame(
            main_content,
            fg_color=self.colors['surface'],
            corner_radius=15,
            border_width=1,
            border_color=self.colors['primary']
        )
        chat_frame.pack(side='left', expand=True, fill='both', padx=(0, 10))

        # Chat header
        chat_header = ctk.CTkFrame(chat_frame, fg_color="transparent", height=50)
        chat_header.pack(fill='x', padx=20, pady=15)
        chat_header.pack_propagate(False)

        ctk.CTkLabel(
            chat_header,
            text="💬 MESSAGES",
            font=("Segoe UI", 16, "bold"),
            text_color=self.colors['primary']
        ).pack(side='left')

        # Chat log
        self.chat_log = ctk.CTkTextbox(
            chat_frame,
            font=("Segoe UI", 12),
            corner_radius=10,
            border_spacing=15,
            fg_color=self.colors['surface_dark'],
            border_color=self.colors['primary'],
            border_width=1
        )
        self.chat_log.pack(expand=True, fill='both', padx=20, pady=(0, 15))
        self.chat_log.configure(state='disabled')

        # Message input area
        input_frame = ctk.CTkFrame(chat_frame, fg_color="transparent", height=60)
        input_frame.pack(fill='x', padx=20, pady=(0, 20))
        input_frame.pack_propagate(False)

        self.message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="✍️ Type your message...",
            font=("Segoe UI", 12),
            height=45,
            state='disabled',
            fg_color=self.colors['surface_dark'],
            border_color=self.colors['primary'],
            border_width=1
        )
        self.message_entry.pack(side='left', expand=True, fill='x', padx=(0, 10))

        self.send_button = ctk.CTkButton(
            input_frame,
            text="Send",
            font=("Segoe UI", 13, "bold"),
            width=100,
            height=45,
            command=self.send_message,
            state='disabled',
            fg_color=self.colors['secondary'],
            hover_color=self.colors['accent']
        )
        self.send_button.pack(side='right')

        # Rooms section
        rooms_frame = ctk.CTkFrame(
            main_content,
            fg_color=self.colors['surface'],
            corner_radius=15,
            width=280,
            border_width=1,
            border_color=self.colors['primary']
        )
        rooms_frame.pack(side='right', fill='y')
        rooms_frame.pack_propagate(False)

        # Rooms header
        rooms_header = ctk.CTkFrame(rooms_frame, fg_color="transparent", height=50)
        rooms_header.pack(fill='x', padx=20, pady=15)
        rooms_header.pack_propagate(False)

        ctk.CTkLabel(
            rooms_header,
            text="🚪 ROOMS",
            font=("Segoe UI", 16, "bold"),
            text_color=self.colors['primary']
        ).pack(side='left')

        # Room list
        self.room_list = ctk.CTkScrollableFrame(
            rooms_frame,
            fg_color=self.colors['surface_dark'],
            corner_radius=10,
            border_color=self.colors['primary'],
            border_width=1
        )
        self.room_list.pack(expand=True, fill='both', padx=20, pady=(0, 15))

        # Room controls
        room_control_frame = ctk.CTkFrame(rooms_frame, fg_color="transparent",
                                          height=60)  # Changed height from 110 to 60
        room_control_frame.pack(fill='x', padx=20, pady=(0, 20))
        room_control_frame.pack_propagate(False)

        join_button = ctk.CTkButton(
            room_control_frame,
            text="Join Room ",
            font=("Segoe UI", 13, "bold"),
            height=45,
            command=self.show_join_room_popup,
            fg_color=self.colors['secondary'],
            hover_color=self.colors['accent']
        )
        join_button.pack(fill='x')

    def show_join_room_popup(self):
        RoomPopup(self.root, self.colors, self.join_room)

    def create_status_bar(self):
        self.status_bar = ctk.CTkLabel(
            self.container,
            text="⚡ Ready to connect",
            font=("Segoe UI", 12),
            fg_color=self.colors['surface'],
            corner_radius=10,
            height=40,
            pady=5
        )
        self.status_bar.pack(fill='x', pady=(15, 10), padx=10)

    def connect(self):
        if not self.chat_client.connected:
            try:
                server_ip = self.ip_entry.get()
                server_port = int(self.port_entry.get())
                username = self.username_entry.get()

                if not username:
                    messagebox.showerror("Error", "Username cannot be empty")
                    return

                success, message = self.chat_client.connect_to_server(server_ip, server_port, username)
                if success:
                    self.update_connection_ui(True)
                    self.append_to_chat(f"Connected to {server_ip}:{server_port}\n")
                    self.update_status(f"Connected as {username}", 'success')
                    threading.Thread(target=self.chat_client.listen_for_messages, daemon=True).start()
                else:
                    self.update_status(f"Connection error: {message}", 'error')
                    messagebox.showerror("Connection Error", message)

            except Exception as e:
                self.update_status(f"Connection error: {str(e)}", 'error')
                messagebox.showerror("Connection Error", str(e))

    def send_message(self):
        message = self.message_entry.get().strip()
        if message:
            success, response = self.chat_client.send_message(message)
            if success:
                self.message_entry.delete(0, 'end')
                self.append_to_chat(response)
            else:
                self.update_status(response, 'error')
                self.append_to_chat(response)

    def join_room(self, room_name):
        if not room_name:
            self.update_status("Please enter a valid room name", 'error')
            return

        success, response = self.chat_client.join_room(room_name)
        if success:
            room_button = ctk.CTkButton(
                self.room_list,
                text=f"📁 {room_name}",
                command=lambda r=room_name: self.leave_room(r),
                fg_color=self.colors['surface'],
                hover_color=self.colors['error'],
                height=35
            )
            room_button.pack(fill='x', pady=5, padx=5)
            self.append_to_chat(f"→ Joined room: {room_name}")
            self.update_status(f"Successfully joined room: {room_name}", 'success')
        else:
            self.update_status(f"Failed to join room: {response}", 'error')

    def leave_room(self, room_name):
        success, response = self.chat_client.leave_room(room_name)
        if success:
            for widget in self.room_list.winfo_children():
                if isinstance(widget, ctk.CTkButton) and widget.cget("text") == f"📁 {room_name}":
                    widget.destroy()
            self.append_to_chat(f"← Left room: {room_name}")
            self.update_status(f"Successfully left room: {room_name}", 'success')
        else:
            self.update_status(f"Failed to leave room: {response}", 'error')

    def handle_incoming_message(self, message):
        self.append_to_chat(message)

    def append_to_chat(self, message):
        self.chat_log.configure(state='normal')
        self.chat_log.insert('end', message + "\n")
        self.chat_log.see('end')
        self.chat_log.configure(state='disabled')

    def update_status(self, message, status_type='info'):
        icon = "⚡" if status_type == 'info' else "✅" if status_type == 'success' else "❌"
        self.status_bar.configure(text=f"{icon} {message}")
        if status_type == 'error':
            self.status_bar.configure(text_color=self.colors['error'])
        elif status_type == 'success':
            self.status_bar.configure(text_color=self.colors['success'])
        else:
            self.status_bar.configure(text_color=self.colors['text'])

    def update_connection_ui(self, connected):
        state = 'disabled' if connected else 'normal'
        opposite_state = 'normal' if connected else 'disabled'
        self.username_entry.configure(state=state)
        self.ip_entry.configure(state=state)
        self.port_entry.configure(state=state)
        self.connect_button.configure(state=state)
        self.message_entry.configure(state=opposite_state)
        self.send_button.configure(state=opposite_state)

    def run(self):
        self.center_window()
        try:
            self.root.iconbitmap('chat_icon.ico')
        except:
            pass
        self.root.mainloop()

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'+{x}+{y}')


if __name__ == "__main__":
    try:
        gui = ChatGUI()
        gui.run()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application failed to start: {str(e)}")
