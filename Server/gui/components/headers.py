import customtkinter as ctk


class ServerHeader:
    """Manages the server header with title and controls"""

    def __init__(self, parent, colors, start_callback, stop_callback):
        self.parent = parent
        self.colors = colors
        self.start_callback = start_callback
        self.stop_callback = stop_callback
        self.header = None
        self.host_entry = None
        self.port_entry = None
        self.start_button = None
        self.stop_button = None

    def create_header(self, server_port):
        """Create the complete header section"""
        self.header = ctk.CTkFrame(
            self.parent,
            corner_radius=16,
            fg_color=self.colors["card"],
            border_width=1,
            border_color=self.colors["primary"]
        )
        self.header.pack(fill="x", pady=(0, 16))

        title = ctk.CTkLabel(
            self.header,
            text="Secure Chat Server",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(side="left", padx=20, pady=12)

        controls = ctk.CTkFrame(self.header, fg_color="transparent")
        controls.pack(side="right", padx=20)

        self.host_entry = ctk.CTkEntry(controls, width=160, placeholder_text="Server IP")
        self.host_entry.insert(0, "0.0.0.0")
        self.host_entry.pack(side="left", padx=5)

        self.port_entry = ctk.CTkEntry(controls, width=80, placeholder_text="Port")
        self.port_entry.insert(0, str(server_port))
        self.port_entry.pack(side="left", padx=5)

        self.start_button = ctk.CTkButton(
            controls,
            text="▶ Start",
            command=self.start_callback,
            fg_color=self.colors["primary"],
            hover_color=self.colors["hover_primary"]
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            controls,
            text="■ Stop",
            command=self.stop_callback,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        return self.header

    def get_server_config(self):
        """Get the server configuration from input fields"""
        return {
            "host": self.host_entry.get(),
            "port": int(self.port_entry.get())
        }

    def update_controls_state(self, server_running):
        """Update the state of control buttons based on server status"""
        if server_running:
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.host_entry.configure(state="disabled")
            self.port_entry.configure(state="disabled")
        else:
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.host_entry.configure(state="normal")
            self.port_entry.configure(state="normal")