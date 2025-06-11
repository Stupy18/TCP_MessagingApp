import customtkinter as ctk


class ServerDialogs:
    """Handles server information and other dialog windows"""

    def __init__(self, colors):
        self.colors = colors

    def show_server_info(self, parent, stats):
        """Display server information and statistics"""
        uptime_str = "0:00:00"
        if stats["uptime"]:
            hours = stats["uptime"].seconds // 3600
            minutes = (stats["uptime"].seconds % 3600) // 60
            seconds = stats["uptime"].seconds % 60
            uptime_str = f"{hours}:{minutes:02d}:{seconds:02d}"

        # Create an info dialog
        info_dialog = ctk.CTkToplevel(parent)
        info_dialog.title("Server Information")
        info_dialog.geometry("500x350")
        info_dialog.resizable(False, False)
        info_dialog.transient(parent)
        info_dialog.grab_set()

        # Set dialog layout
        info_dialog.grid_columnconfigure(0, weight=1)
        info_dialog.grid_rowconfigure(2, weight=1)

        # Title
        title_label = ctk.CTkLabel(
            info_dialog,
            text="Server Information",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.grid(row=0, column=0, pady=(20, 0), sticky="ew")

        # Separator
        separator = ctk.CTkFrame(info_dialog, height=2, fg_color=self.colors["primary"])
        separator.grid(row=1, column=0, sticky="ew", padx=20, pady=(10, 15))

        # Content frame
        content_frame = ctk.CTkFrame(info_dialog, fg_color="transparent")
        content_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)

        # Server info section
        info_section = ctk.CTkFrame(content_frame, fg_color=self.colors["card"], corner_radius=10)
        info_section.pack(fill="both", expand=True)

        # Two columns layout
        left_col = ctk.CTkFrame(info_section, fg_color="transparent")
        left_col.pack(side="left", fill="both", expand=True, padx=15, pady=15)

        right_col = ctk.CTkFrame(info_section, fg_color="transparent")
        right_col.pack(side="right", fill="both", expand=True, padx=15, pady=15)

        # Server info
        ctk.CTkLabel(
            left_col,
            text="Connection",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        ).pack(fill="x", pady=(0, 5))

        ctk.CTkLabel(
            left_col,
            text=f"Host: {stats['host'] or 'Not running'}",
            anchor="w"
        ).pack(fill="x", pady=2)

        ctk.CTkLabel(
            left_col,
            text=f"Port: {stats['port']}",
            anchor="w"
        ).pack(fill="x", pady=2)

        ctk.CTkLabel(
            left_col,
            text=f"Status: {'Running' if stats['running'] else 'Stopped'}",
            anchor="w"
        ).pack(fill="x", pady=2)

        # Stats
        ctk.CTkLabel(
            right_col,
            text="Statistics",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        ).pack(fill="x", pady=(0, 5))

        ctk.CTkLabel(
            right_col,
            text=f"Total Connections: {stats['total_connections']}",
            anchor="w"
        ).pack(fill="x", pady=2)

        ctk.CTkLabel(
            right_col,
            text=f"Active Connections: {stats['active_connections']}",
            anchor="w"
        ).pack(fill="x", pady=2)

        ctk.CTkLabel(
            right_col,
            text=f"Total Messages: {stats['total_messages']}",
            anchor="w"
        ).pack(fill="x", pady=2)

        ctk.CTkLabel(
            right_col,
            text=f"Active Rooms: {stats['active_rooms']}",
            anchor="w"
        ).pack(fill="x", pady=2)

        ctk.CTkLabel(
            right_col,
            text=f"Uptime: {uptime_str}",
            anchor="w"
        ).pack(fill="x", pady=2)

        # Close button
        close_button = ctk.CTkButton(
            info_dialog,
            text="Close",
            command=info_dialog.destroy,
            fg_color=self.colors["primary"],
            hover_color=self.colors["hover_primary"],
            width=120
        )
        close_button.grid(row=3, column=0, pady=(0, 20))

        # Center the dialog
        info_dialog.update_idletasks()
        width = info_dialog.winfo_width()
        height = info_dialog.winfo_height()
        x = (info_dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (info_dialog.winfo_screenheight() // 2) - (height // 2)
        info_dialog.geometry(f'+{x}+{y}')