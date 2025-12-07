import customtkinter as ctk


class HeaderSection:
    """Manages the header section with connection settings"""

    def __init__(self, parent, colors, connect_callback):
        self.parent = parent
        self.colors = colors
        self.connect_callback = connect_callback
        self.header = None
        self.ip_entry = None
        self.port_entry = None
        self.username_entry = None
        self.connect_button = None

    def create_header_section(self):
        """Create the complete header section with connection settings"""
        self.header = ctk.CTkFrame(
            self.parent,
            fg_color="transparent",
            height=100
        )
        self.header.pack(fill='x', pady=(10, 20))

        # Connection settings
        settings_frame = ctk.CTkFrame(
            self.header,
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
            command=self.connect_callback,
            corner_radius=10,
            fg_color=self.colors['primary'],
            hover_color=self.colors['primary_hover']
        )
        self.connect_button.pack(side='right', padx=20)

        return self.header

    def get_connection_details(self):
        """Get the connection details from the input fields"""
        return {
            'ip': self.ip_entry.get(),
            'port': self.port_entry.get(),
            'username': self.username_entry.get().strip()
        }

    def set_username(self, username):
        """Set the username in the input field"""
        self.username_entry.delete(0, 'end')
        self.username_entry.insert(0, username)

    def update_connection_ui(self, connected):
        """Update UI elements based on connection state"""
        state = 'disabled' if connected else 'normal'
        self.username_entry.configure(state=state)
        self.ip_entry.configure(state=state)
        self.port_entry.configure(state=state)
        self.connect_button.configure(state=state)

    def setup_connect_button_animation(self, root, is_connected_callback):
        """Setup the pulsing animation for the connect button"""

        def pulse_connect_button():
            if not is_connected_callback():
                self.connect_button.configure(fg_color=self.colors['primary_hover'])
                root.after(700, lambda: self.connect_button.configure(fg_color=self.colors['primary']))
                root.after(1400, pulse_connect_button)

        pulse_connect_button()