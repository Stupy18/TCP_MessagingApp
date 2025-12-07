import os
from tkinter import messagebox
import customtkinter as ctk
from Client.functionality.resource_path import get_resource_path

class LoginPopup:
    def __init__(self, parent):
        self.parent = parent
        self.username = None

        # Get the directory containing the current script
        self.script_dir = os.path.dirname(os.path.abspath(__file__))

        self.create_popup()
        self.animate_in()




    def create_popup(self):
        # Create the popup window
        self.popup = ctk.CTkToplevel(self.parent)
        self.popup.title("")
        self.popup.geometry("400x300")
        self.popup.resizable(False, False)
        self.popup.protocol("WM_DELETE_WINDOW", self.on_close)

        def load_icon():
            try:
                # First try development path
                self.popup.iconbitmap('../assets/join.ico')
            except:
                try:
                    # Then try compiled path
                    icon_path = get_resource_path("join.ico")
                    self.popup.iconbitmap(icon_path)
                except Exception as e:
                    print(f"Warning: Could not load icon: {e}")

        self.popup.after(201, load_icon)


        # Remove default window decorations
        self.popup.transient(self.parent)
        self.popup.attributes('-topmost', True)

        # Configure the popup
        self.popup.configure(fg_color='#1C1C1E')

        # Initial state (for animation)
        self.popup.attributes('-alpha', 0)

        # Center the popup
        self.center_popup()

        # Create content
        title_label = ctk.CTkLabel(
            self.popup,
            text="Welcome to SecureTransport",
            font=("Segoe UI", 24, "bold"),
            text_color='#F5F5F7'
        )
        title_label.pack(pady=(40, 20))

        # Username entry
        self.username_entry = ctk.CTkEntry(
            self.popup,
            width=300,
            height=45,
            placeholder_text="Enter your username...",
            font=("Segoe UI", 14),
            fg_color='#262628',
            border_color='#1F4690',
            text_color='#F5F5F7'
        )
        self.username_entry.pack(pady=20)

        # Enter button
        enter_btn = ctk.CTkButton(
            self.popup,
            text="Enter Chat ",
            width=200,
            height=45,
            font=("Segoe UI", 15, "bold"),
            fg_color='#1F4690',
            hover_color='#1E88E5',
            command=self.submit
        )
        enter_btn.pack(pady=20)

        # Bind Enter key
        self.username_entry.bind('<Return>', lambda e: self.submit())

        # Make window draggable
        self.popup.bind('<Button-1>', self.start_move)
        self.popup.bind('<B1-Motion>', self.on_move)

    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def on_move(self, event):
        deltax = event.x - self.x
        deltay = event.y - self.y
        x = self.popup.winfo_x() + deltax
        y = self.popup.winfo_y() + deltay
        self.popup.geometry(f"+{x}+{y}")

    def center_popup(self):
        # Center the popup on screen
        self.popup.update_idletasks()
        width = 400
        height = 300
        x = (self.popup.winfo_screenwidth() // 2) - (width // 2)
        y = (self.popup.winfo_screenheight() // 2) - (height // 2)
        self.popup.geometry(f"{width}x{height}+{x}+{y}")

    def animate_in(self):
        alpha = 0.0
        while alpha < 1.0:
            alpha += 0.1
            self.popup.attributes('-alpha', alpha)
            self.popup.update()
            self.popup.after(20)

    def animate_out(self):
        alpha = 1.0
        while alpha > 0:
            alpha -= 0.1
            self.popup.attributes('-alpha', alpha)
            self.popup.update()
            self.popup.after(20)

    def submit(self):
        self.username = self.username_entry.get().strip()
        if self.username:
            self.animate_out()
            self.popup.destroy()
        else:
            messagebox.showerror("Error", "Username cannot be empty")

    def get_username(self):
        self.popup.wait_window()
        return self.username

    def on_close(self):
        """Handle window close button (X) properly"""
        self.username = None  # Set username to None so app exits
        self.popup.destroy()