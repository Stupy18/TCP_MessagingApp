import customtkinter as ctk


class ThemeManager:
    """Manages application themes and styling"""

    def __init__(self):
        self.setup_appearance()
        self.colors = self._define_colors()

    def setup_appearance(self):
        """Set up the global appearance settings"""
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

    def _define_colors(self):
        """Define the application color palette"""
        return {
            'primary': '#1F4690',  # Deep blue - conveys trust and reliability, suitable for CTAs
            'primary_hover': '#1E88E5',  # Medium blue - elegant and eye-catching hover state
            'secondary': '#0077B6',  # Muted teal - secondary actions, professional and calming
            'accent': '#5A189A',  # Rich purple - adds depth and a sense of premium quality for special elements
            'success': '#2E7D32',  # Dark green - sophisticated green for success states
            'error': '#B00020',  # Deep red - serious and clear error indication
            'warning': '#FF8C00',  # Warm amber - attention-grabbing but not overly aggressive
            'surface': '#1C1C1E',  # Charcoal black - main background, professional and minimal
            'surface_dark': '#121212',  # Deep black - darker secondary background, suitable for contrast
            'text': '#F5F5F7',  # Light gray - softer white for primary text, reduces eye strain
            'text_secondary': '#C5C6C7',  # Medium gray - secondary text for subtle emphasis

            # New additions for more depth
            'surface_raised': '#2C2C2E',  # Slightly lighter than surface for elevated components
            'border': '#3C3C3F',  # Dark gray - subtle borders for definition without high contrast
            'border_light': '#55575A',  # Mid gray - highlighted borders, more visible but not stark
            'input_background': '#262628',  # Dark gray - input field background, makes inputs stand out slightly
            'badge_background': 'rgba(31, 70, 144, 0.1)',  # Transparent blue - subtle, professional badge background
            'shadow': '0px 4px 8px rgba(0, 0, 0, 0.15)'  # Slightly deeper shadow for a more refined elevation
        }

    def get_colors(self):
        """Get the color palette"""
        return self.colors

    def apply_window_effects(self, window):
        """Apply platform-specific window effects"""
        import sys

        if sys.platform.startswith('win'):
            window.wm_attributes('-transparentcolor', 'white')
            window.attributes('-alpha', 0.4)  # Slight transparency

        # Instead of overrideredirect, let's use these attributes
        window.attributes('-alpha', 1.0)  # Set transparency
        window.wm_attributes('-topmost', False)  # Don't keep on top