import tkinter
import customtkinter as ctk


class RoomsSection:
    """Manages the rooms panel with room list and controls"""

    def __init__(self, parent, colors, join_room_popup_callback, select_room_callback, leave_room_callback):
        self.parent = parent
        self.colors = colors
        self.join_room_popup_callback = join_room_popup_callback
        self.select_room_callback = select_room_callback
        self.leave_room_callback = leave_room_callback
        self.rooms_frame = None
        self.room_list = None
        self.room_buttons = {}  # Track room buttons for management
        self.selected_room = None

    def create_rooms_section(self):
        """Create the complete rooms section"""
        # Rooms section
        self.rooms_frame = ctk.CTkFrame(
            self.parent,
            fg_color=self.colors['surface'],
            corner_radius=15,
            width=280,
            border_width=1,
            border_color=self.colors['primary']
        )
        self.rooms_frame.pack(side='right', fill='y')
        self.rooms_frame.pack_propagate(False)

        # Rooms header
        rooms_header = ctk.CTkFrame(self.rooms_frame, fg_color="transparent", height=50)
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
            self.rooms_frame,
            fg_color=self.colors['surface_dark'],
            corner_radius=10,
            border_color=self.colors['primary'],
            border_width=1
        )
        self.room_list.pack(expand=True, fill='both', padx=20, pady=(0, 15))

        # Room controls
        room_control_frame = ctk.CTkFrame(self.rooms_frame, fg_color="transparent", height=100)
        room_control_frame.pack(fill='x', padx=20, pady=(0, 20))
        room_control_frame.pack_propagate(False)

        join_button = ctk.CTkButton(
            room_control_frame,
            text="Join Room ",
            font=("Segoe UI", 13, "bold"),
            height=45,
            command=self.join_room_popup_callback,
            fg_color=self.colors['secondary'],
            hover_color=self.colors['accent']
        )
        join_button.pack(fill='x', pady=(0, 10))

        # Leave room button
        self.leave_button = ctk.CTkButton(
            room_control_frame,
            text="Leave Room",
            font=("Segoe UI", 13, "bold"),
            height=45,
            command=self._leave_selected_room,
            fg_color=self.colors['error'],
            hover_color="#D32F2F"
        )
        self.leave_button.pack(fill='x')

        return self.rooms_frame

    def _leave_selected_room(self):
        """Leave the currently selected room"""
        if self.selected_room:
            self.leave_room_callback(self.selected_room)

    def add_room_button(self, room_name):
        """Add a room button to the room list"""
        # Check if button already exists
        if room_name in self.room_buttons:
            return

        # Create room button
        room_button = ctk.CTkButton(
            self.room_list,
            text=f"📁 {room_name}",
            command=lambda r=room_name: self.select_room_callback(r),
            fg_color=self.colors['surface'],
            hover_color=self.colors['secondary'],
            height=35
        )
        room_button.pack(fill='x', pady=5, padx=5)

        # Store reference
        self.room_buttons[room_name] = room_button

        # Add context menu for right-click
        def show_context_menu(event):
            menu = tkinter.Menu(None, tearoff=0, bg=self.colors['surface'], fg=self.colors['text'])
            menu.add_command(label="Leave Room", command=lambda: self.leave_room_callback(room_name))
            menu.tk_popup(event.x_root, event.y_root)

        room_button.bind("<Button-3>", show_context_menu)  # Right-click

        return room_button

    def remove_room_button(self, room_name):
        """Remove a room button from the room list"""
        if room_name in self.room_buttons:
            self.room_buttons[room_name].destroy()
            del self.room_buttons[room_name]

    def highlight_selected_room(self, selected_room_name):
        """Highlight the selected room button and unhighlight others"""
        self.selected_room = selected_room_name
        for room_name, button in self.room_buttons.items():
            if room_name == selected_room_name:
                button.configure(fg_color=self.colors['primary'])
            else:
                button.configure(fg_color=self.colors['surface'])

    def get_room_buttons(self):
        """Get all room buttons (for iteration)"""
        return list(self.room_buttons.items())

    def clear_all_rooms(self):
        """Clear all room buttons"""
        for button in self.room_buttons.values():
            button.destroy()
        self.room_buttons.clear()

    def room_exists(self, room_name):
        """Check if a room button exists"""
        return room_name in self.room_buttons