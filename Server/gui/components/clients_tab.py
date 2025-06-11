import customtkinter as ctk
from tkinter import messagebox


class ClientsTab:
    """Manages the connected clients tab with client list and controls"""

    def __init__(self, parent, colors, disconnect_selected_callback, disconnect_all_callback, refresh_callback):
        self.parent = parent
        self.colors = colors
        self.disconnect_selected_callback = disconnect_selected_callback
        self.disconnect_all_callback = disconnect_all_callback
        self.refresh_callback = refresh_callback
        self.clients_scrollable = None
        self.client_frames = []
        self.client_data = []

    def setup_clients_tab(self):
        """Setup the complete clients tab"""
        clients_frame = self.parent

        # Client controls
        client_controls = ctk.CTkFrame(clients_frame, fg_color="transparent")
        client_controls.pack(fill="x", pady=10)

        disconnect_selected = ctk.CTkButton(
            client_controls,
            text="Disconnect Selected",
            command=self.disconnect_selected_callback,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=160
        )
        disconnect_selected.pack(side="left", padx=5)

        disconnect_all = ctk.CTkButton(
            client_controls,
            text="Disconnect All",
            command=self.disconnect_all_callback,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=120
        )
        disconnect_all.pack(side="left", padx=5)

        refresh_clients = ctk.CTkButton(
            client_controls,
            text="↻ Refresh",
            command=self.refresh_callback,
            fg_color=self.colors["primary"],
            hover_color=self.colors["hover_primary"],
            width=100
        )
        refresh_clients.pack(side="left", padx=5)

        # Client list container
        client_list_frame = ctk.CTkFrame(clients_frame, fg_color="#1e1e1e", corner_radius=6)
        client_list_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Headers
        headers_frame = ctk.CTkFrame(client_list_frame, fg_color="#2a2a2a", height=30)
        headers_frame.pack(fill="x", padx=2, pady=(2, 0))
        headers_frame.pack_propagate(False)

        header_texts = ["Username", "IP", "Port", "Connected Time", "Active Rooms"]  # Add Username column
        header_widths = [120, 120, 80, 120, 200]  # Adjust widths
        for i, text in enumerate(header_texts):
            header = ctk.CTkLabel(
                headers_frame,
                text=text,
                font=ctk.CTkFont(weight="bold", size=12),
                width=header_widths[i]
            )
            header.pack(side="left", padx=5)

        # Scrollable frame for client items
        self.clients_scrollable = ctk.CTkScrollableFrame(
            client_list_frame,
            fg_color="#1e1e1e",
            corner_radius=0
        )
        self.clients_scrollable.pack(expand=True, fill="both", padx=2, pady=(0, 2))

    def create_client_item(self, client_data):
        """Create a client item in the list"""
        # Create a frame for this client item
        item_frame = ctk.CTkFrame(self.clients_scrollable, fg_color="#232323", height=40, corner_radius=6)
        item_frame.pack(fill="x", padx=5, pady=3)
        item_frame.pack_propagate(False)

        # Store data for selection
        item_frame.data = client_data

        # Add client data to frame
        username_label = ctk.CTkLabel(item_frame, text=client_data.get("username", "Unknown"), width=120)
        username_label.pack(side="left", padx=5)

        ip_label = ctk.CTkLabel(item_frame, text=client_data["ip"], width=120)
        ip_label.pack(side="left", padx=5)

        port_label = ctk.CTkLabel(item_frame, text=client_data["port"], width=80)
        port_label.pack(side="left", padx=5)

        time_label = ctk.CTkLabel(item_frame, text=client_data["connected_time"], width=120)
        time_label.pack(side="left", padx=5)

        rooms_text = ", ".join(client_data["rooms"]) or "None"
        rooms_label = ctk.CTkLabel(item_frame, text=rooms_text, width=200)
        rooms_label.pack(side="left", padx=5)

        # Add selection behavior
        def on_click(event):
            self.select_client_item(item_frame)

        item_frame.bind("<Button-1>", on_click)
        for widget in item_frame.winfo_children():
            widget.bind("<Button-1>", on_click)

        return item_frame

    def select_client_item(self, item_frame):
        """Toggle selection state of a client item"""
        # Toggle selection
        if hasattr(item_frame, "selected") and item_frame.selected:
            item_frame.configure(fg_color="#232323")
            item_frame.selected = False
        else:
            item_frame.configure(fg_color=self.colors["primary"])
            item_frame.selected = True

    def update_client_list(self, client_list):
        """Update the client list display"""
        # Clear existing items
        for frame in self.client_frames:
            frame.destroy()
        self.client_frames = []

        # Store client data
        self.client_data = client_list

        # Create new items
        for client in client_list:
            client_frame = self.create_client_item(client)
            self.client_frames.append(client_frame)

    def get_selected_clients(self):
        """Get list of selected client frames"""
        return [frame for frame in self.client_frames if hasattr(frame, "selected") and frame.selected]