import customtkinter as ctk


class StatusBar:
    """Manages the application status bar"""

    def __init__(self, parent, colors):
        self.parent = parent
        self.colors = colors
        self.status_bar = None

    def create_status_bar(self):
        """Create the status bar"""
        self.status_bar = ctk.CTkLabel(
            self.parent,
            text="⚡ Ready to connect",
            font=("Segoe UI", 12),
            fg_color=self.colors['surface'],
            corner_radius=10,
            height=40,
            pady=5
        )
        self.status_bar.pack(fill='x', pady=(15, 10), padx=10)

        return self.status_bar

    def update_status(self, message, status_type='info'):
        """Update the status bar with a message and appropriate styling"""
        icon = "⚡" if status_type == 'info' else "✅" if status_type == 'success' else "❌"
        self.status_bar.configure(text=f"{icon} {message}")

        if status_type == 'error':
            self.status_bar.configure(text_color=self.colors['error'])
        elif status_type == 'success':
            self.status_bar.configure(text_color=self.colors['success'])
        else:
            self.status_bar.configure(text_color=self.colors['text'])

    def set_ready_status(self):
        """Set the status to ready state"""
        self.update_status("Ready to connect", 'info')

    def set_connecting_status(self, server_info):
        """Set status to connecting"""
        self.update_status(f"Connecting to {server_info}...", 'info')

    def set_connected_status(self, username, server_info):
        """Set status to connected"""
        self.update_status(f"Connected as {username} to {server_info}", 'success')

    def set_error_status(self, error_message):
        """Set status to error"""
        self.update_status(f"Error: {error_message}", 'error')

    def set_room_status(self, room_name, action):
        """Set status for room operations"""
        if action == 'joining':
            self.update_status(f"Attempting to join room: {room_name}...", 'info')
        elif action == 'joined':
            self.update_status(f"Successfully joined room: {room_name}", 'success')
        elif action == 'left':
            self.update_status(f"Successfully left room: {room_name}", 'success')
        elif action == 'error':
            self.update_status(f"Failed to join room: {room_name}", 'error')