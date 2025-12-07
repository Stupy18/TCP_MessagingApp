import customtkinter as ctk


class StatsCards:
    """Manages the statistics display cards"""

    def __init__(self, parent, colors):
        self.parent = parent
        self.colors = colors
        self.stats_frame = None
        self.conn_card = None
        self.msg_card = None
        self.room_card = None
        self.uptime_card = None

    def create_stats_section(self):
        """Create the complete statistics section"""
        self.stats_frame = ctk.CTkFrame(self.parent, fg_color="transparent")
        self.stats_frame.pack(fill="x", pady=(0, 16))

        self.conn_card = self.create_stat_card(self.stats_frame, "Connections", "0", self.colors["primary"])
        self.msg_card = self.create_stat_card(self.stats_frame, "Messages", "0", self.colors["accent"])
        self.room_card = self.create_stat_card(self.stats_frame, "Rooms", "0", self.colors["success"])
        self.uptime_card = self.create_stat_card(self.stats_frame, "Uptime", "0:00:00", self.colors["warning"])

        return self.stats_frame

    def create_stat_card(self, parent, title, value, color):
        """Create an individual statistics card"""
        card = ctk.CTkFrame(
            parent,
            corner_radius=16,
            fg_color=self.colors["card"],
            border_width=1,
            border_color=color
        )
        card.pack(side="left", expand=True, fill="x", padx=8)

        strip = ctk.CTkFrame(card, height=5, corner_radius=0, fg_color=color)
        strip.pack(fill="x", pady=(0, 5))

        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", padx=10)

        label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=20, weight="bold")
        )
        label.pack(anchor="w", padx=10, pady=(0, 10))

        return label

    def update_stats(self, stats):
        """Update all statistics cards with new data"""
        if stats["running"]:
            self.conn_card.configure(text=str(stats["active_connections"]))
            self.msg_card.configure(text=str(stats["total_messages"]))
            self.room_card.configure(text=str(stats["active_rooms"]))

            if stats["uptime"]:
                seconds = stats["uptime"].seconds
                uptime_str = f"{seconds // 3600}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"
                self.uptime_card.configure(text=uptime_str)

    def reset_stats(self):
        """Reset all statistics cards to zero"""
        self.conn_card.configure(text="0")
        self.msg_card.configure(text="0")
        self.room_card.configure(text="0")
        self.uptime_card.configure(text="0:00:00")