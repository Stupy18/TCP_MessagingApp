import os

import customtkinter as ctk
class RoomPopup:
    def __init__(self, parent, colors, join_callback):
        self.parent = parent
        self.colors = colors
        self.join_callback = join_callback
        self.create_popup()
        self.animate_in()

    def create_popup(self):
        # Create the popup window
        self.popup = ctk.CTkToplevel(self.parent)
        self.popup.title("")
        self.popup.geometry("400x250")
        self.popup.resizable(False, False)

        self.popup.after(201, lambda: self.popup.iconbitmap('../assets/room.ico'))



        # Remove default window decorations
        self.popup.transient(self.parent)
        self.popup.attributes('-topmost', True)

        # Configure the popup
        self.popup.configure(fg_color=self.colors['surface'])

        # Initial state (for animation)
        self.popup.attributes('-alpha', 0)

        # Center the popup
        self.center_popup()

        # Create content
        title_label = ctk.CTkLabel(
            self.popup,
            text="Join New Room",
            font=("Segoe UI", 20, "bold"),
            text_color=self.colors['text']
        )
        title_label.pack(pady=(30, 20))

        # Room name entry
        self.room_entry = ctk.CTkEntry(
            self.popup,
            width=300,
            height=45,
            placeholder_text="Enter room name...",
            font=("Segoe UI", 14),
            fg_color=self.colors['surface_dark'],
            border_color=self.colors['primary'],
            text_color=self.colors['text']
        )
        self.room_entry.pack(pady=20)

        # Buttons frame
        buttons_frame = ctk.CTkFrame(
            self.popup,
            fg_color="transparent"
        )
        buttons_frame.pack(pady=20)

        # Cancel button
        cancel_btn = ctk.CTkButton(
            buttons_frame,
            text="Cancel",
            width=120,
            height=40,
            fg_color=self.colors['surface_dark'],
            hover_color=self.colors['error'],
            text_color=self.colors['text'],
            command=self.close
        )
        cancel_btn.pack(side='left', padx=10)

        # Join button
        join_btn = ctk.CTkButton(
            buttons_frame,
            text="Join Room",
            width=120,
            height=40,
            fg_color=self.colors['primary'],
            hover_color=self.colors['primary_hover'],
            command=self.join
        )
        join_btn.pack(side='left', padx=10)

        # Bind Enter key
        self.room_entry.bind('<Return>', lambda e: self.join())
        self.room_entry.bind('<Escape>', lambda e: self.close())

    def center_popup(self):
        # Center the popup relative to the parent window
        self.popup.update_idletasks()
        parent_x = self.parent.winfo_x()
        parent_y = self.parent.winfo_y()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()

        popup_width = 400
        popup_height = 250

        x = parent_x + (parent_width - popup_width) // 2
        y = parent_y + (parent_height - popup_height) // 2

        self.popup.geometry(f"{popup_width}x{popup_height}+{x}+{y}")

    def animate_in(self):
        # Fade in animation
        alpha = 0.0
        while alpha < 1.0:
            alpha += 0.1
            self.popup.attributes('-alpha', alpha)
            self.popup.update()
            self.parent.after(20)

    def animate_out(self):
        # Fade out animation
        alpha = 1.0
        while alpha > 0:
            alpha -= 0.1
            self.popup.attributes('-alpha', alpha)
            self.popup.update()
            self.parent.after(20)

    def close(self):
        self.animate_out()
        self.popup.destroy()

    def join(self):
        room_name = self.room_entry.get().strip()
        if room_name:
            self.join_callback(room_name)
            self.close()