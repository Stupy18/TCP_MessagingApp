import customtkinter as ctk
from tkinter import messagebox


class RoomsTab:
    """Manages the chat rooms tab with room list and controls"""

    def __init__(self, parent, colors, close_selected_callback, close_all_callback, refresh_callback):
        self.parent = parent
        self.colors = colors
        self.close_selected_callback = close_selected_callback
        self.close_all_callback = close_all_callback
        self.refresh_callback = refresh_callback
        self.rooms_scrollable = None
        self.room_frames = []
        self.room_data = []

    def setup_rooms_tab(self):
        """Setup the complete rooms tab"""
        rooms_frame = self.parent

        # Room controls
        room_controls = ctk.CTkFrame(rooms_frame, fg_color="transparent")
        room_controls.pack(fill="x", pady=10)

        close_selected = ctk.CTkButton(
            room_controls,
            text="Close Selected Room",
            command=self.close_selected_callback,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=160
        )
        close_selected.pack(side="left", padx=5)

        close_all = ctk.CTkButton(
            room_controls,
            text="Close All Rooms",
            command=self.close_all_callback,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=120
        )
        close_all.pack(side="left", padx=5)

        refresh_rooms = ctk.CTkButton(
            room_controls,
            text="↻ Refresh",
            command=self.refresh_callback,
            fg_color=self.colors["primary"],
            hover_color=self.colors["hover_primary"],
            width=100
        )
        refresh_rooms.pack(side="left", padx=5)

        # Room list frame
        room_list_frame = ctk.CTkFrame(rooms_frame, fg_color="#1e1e1e", corner_radius=6)
        room_list_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Headers
        room_headers_frame = ctk.CTkFrame(room_list_frame, fg_color="#2a2a2a", height=30)
        room_headers_frame.pack(fill="x", padx=2, pady=(2, 0))
        room_headers_frame.pack_propagate(False)

        room_header_texts = ["Room Name", "Active Users", "Messages"]
        room_header_widths = [300, 100, 100]
        for i, text in enumerate(room_header_texts):
            header = ctk.CTkLabel(
                room_headers_frame,
                text=text,
                font=ctk.CTkFont(weight="bold", size=12),
                width=room_header_widths[i]
            )
            header.pack(side="left", padx=5)

        # Scrollable frame for room items
        self.rooms_scrollable = ctk.CTkScrollableFrame(
            room_list_frame,
            fg_color="#1e1e1e",
            corner_radius=0
        )
        self.rooms_scrollable.pack(expand=True, fill="both", padx=2, pady=(0, 2))

    def create_room_item(self, room_data):
        """Create a room item in the list"""
        # Create a frame for this room item
        item_frame = ctk.CTkFrame(self.rooms_scrollable, fg_color="#232323", height=40, corner_radius=6)
        item_frame.pack(fill="x", padx=5, pady=3)
        item_frame.pack_propagate(False)

        # Store data for selection
        item_frame.data = room_data

        # Add room data to frame
        name_label = ctk.CTkLabel(item_frame, text=room_data["name"], width=300)
        name_label.pack(side="left", padx=5)

        users_label = ctk.CTkLabel(item_frame, text=str(room_data["active_users"]), width=100)
        users_label.pack(side="left", padx=5)

        messages_label = ctk.CTkLabel(item_frame, text=room_data["message_count"], width=100)
        messages_label.pack(side="left", padx=5)

        # Add selection behavior
        def on_click(event):
            self.select_room_item(item_frame)

        item_frame.bind("<Button-1>", on_click)
        for widget in item_frame.winfo_children():
            widget.bind("<Button-1>", on_click)

        return item_frame

    def select_room_item(self, item_frame):
        """Toggle selection state of a room item"""
        # Toggle selection
        if hasattr(item_frame, "selected") and item_frame.selected:
            item_frame.configure(fg_color="#232323")
            item_frame.selected = False
        else:
            item_frame.configure(fg_color=self.colors["primary"])
            item_frame.selected = True

    def update_rooms_list(self, room_list):
        """Update the room list display"""
        # Clear existing items
        for frame in self.room_frames:
            frame.destroy()
        self.room_frames = []

        # Store room data
        self.room_data = room_list

        # Create new items
        for room in room_list:
            room_frame = self.create_room_item(room)
            self.room_frames.append(room_frame)

    def get_selected_rooms(self):
        """Get list of selected room frames"""
        return [frame for frame in self.room_frames if hasattr(frame, "selected") and frame.selected]