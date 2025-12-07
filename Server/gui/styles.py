import customtkinter as ctk


class ServerThemeManager:
    """Manages server GUI themes and styling"""

    def __init__(self):
        self.setup_appearance()
        self.colors = self._define_colors()

    def setup_appearance(self):
        """Set up the global appearance settings"""
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

    def _define_colors(self):
        """Define the server application color palette"""
        return {
            "primary": "#3a7ebf",
            "hover_primary": "#2b5d8b",
            "accent": "#7e3abf",
            "success": "#2D9D78",
            "warning": "#e6b422",
            "danger": "#e63946",
            "background": "#1e1e1e",
            "card": "#2a2a2a",
            "text": "#ffffff",
            "text_secondary": "#a0a0a0"
        }

    def get_colors(self):
        """Get the color palette"""
        return self.colors