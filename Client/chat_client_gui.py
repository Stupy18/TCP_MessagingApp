import sys
import customtkinter as ctk
from tkinter import messagebox

# Add the project root to the path for imports
import os

from LoginPopup import LoginPopup
from Client.RoomPopup import RoomPopup
from Client.gui.components.event_handlers import EventHandlers
from Client.functionality.resource_path import get_resource_path

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Client.functionality.chat_client import ChatClient


from Client.gui.styles import ThemeManager
from Client.gui.components.header_section import HeaderSection
from Client.gui.components.chat_section import ChatSection
from Client.gui.components.rooms_section import RoomsSection
from Client.gui.components.status_bar import StatusBar


class ChatGUI:


    def __init__(self):
        # Initialize theme manager first
        self.theme_manager = ThemeManager()
        self.colors = self.theme_manager.get_colors()

        # Initialize main window
        self.root = ctk.CTk()
        self.root.withdraw()  # Hide main window initially

        # Show login popup and get username
        login = LoginPopup(self.root)
        username = login.get_username()

        if username:
            # Initialize chat client
            self.chat_client = ChatClient()

            # Initialize GUI components
            self._initialize_components()

            # Setup the main GUI
            self._setup_main_window()
            self._create_layout()

            # Setup event handlers and callbacks
            self.event_handlers.setup_callbacks()

            # Pre-fill username
            self.header_section.set_username(username)

            # Show main window
            self.root.deiconify()
            self.root.update()
            self.center_window()
        else:
            self.root.destroy()  # Exit if no username provided
            return

    def _initialize_components(self):
        """Initialize all GUI components"""
        # Create a main container first
        self.container = ctk.CTkFrame(
            self.root,
            fg_color=self.colors['surface_dark'],
            corner_radius=0,
            border_width=0
        )

        # Initialize component sections
        self.header_section = HeaderSection(
            self.container,
            self.colors,
            self._handle_connect_wrapper
        )

        self.chat_section = ChatSection(
            None,  # Will be set when main section is created
            self.colors,
            self._handle_send_message_wrapper
        )

        self.rooms_section = RoomsSection(
            None,  # Will be set when main section is created
            self.colors,
            self._show_join_room_popup,
            self._handle_select_room_wrapper,
            self._handle_leave_room_wrapper
        )

        self.status_bar = StatusBar(self.container, self.colors)

        # Initialize event handlers
        self.event_handlers = EventHandlers(
            self.root,
            self.chat_client,
            self.header_section,
            self.chat_section,
            self.rooms_section,
            self.status_bar
        )

    def _setup_main_window(self):
        """Setup the main window properties"""
        self.root.title("Secure Chat")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Load window icon
        def load_icon():
            try:
                # First try development path
                self.root.iconbitmap("../assets/icon.ico")
            except:
                try:
                    # Then try compiled path
                    icon_path = get_resource_path("icon.ico")
                    self.root.iconbitmap(icon_path)
                except Exception as e:
                    print(f"Warning: Could not load icon: {e}")

        self.root.after(201, load_icon)

        # Apply theme effects
        self.theme_manager.apply_window_effects(self.root)

        # Setup window protocols
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit)
        self.root.update_idletasks()

    def _create_layout(self):
        """Create the main layout using components"""
        # Pack main container
        self.container.pack(expand=True, fill='both')

        # Create header section
        self.header_section.create_header_section()

        # Create main content area
        main_content = ctk.CTkFrame(
            self.container,
            fg_color="transparent"
        )
        main_content.pack(expand=True, fill='both', padx=10, pady=10)

        # Update parent references for main content components
        self.chat_section.parent = main_content
        self.rooms_section.parent = main_content

        # Create chat and rooms sections
        self.chat_section.create_chat_section()
        self.rooms_section.create_rooms_section()

        # Create status bar
        self.status_bar.create_status_bar()

        # Setup bindings and animations
        self._setup_bindings_and_animations()

    def _setup_bindings_and_animations(self):
        """Setup keyboard bindings and animations"""
        # Setup chat section bindings
        self.chat_section.setup_bindings(self.root)

        # Setup header animation
        self.header_section.setup_connect_button_animation(
            self.root,
            lambda: self.chat_client.connected
        )

    def _handle_connect_wrapper(self):
        """Wrapper for connect event handling"""
        self.event_handlers.handle_connect()

    def _handle_send_message_wrapper(self):
        """Wrapper for send message event handling"""
        self.event_handlers.handle_send_message()

    def _handle_select_room_wrapper(self, room_name):
        """Wrapper for room selection event handling"""
        self.event_handlers.handle_select_room(room_name)

    def _handle_leave_room_wrapper(self, room_name):
        """Wrapper for leave room event handling"""
        self.event_handlers.handle_leave_room(room_name)

    def _show_join_room_popup(self):
        """Show the join room popup"""

        def join_room_callback(room_name, password=None):
            self.event_handlers.handle_join_room(room_name, password)

        RoomPopup(self.root, self.colors, join_room_callback)

    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'+{x}+{y}')

    def run(self):
        """Start the GUI main loop"""

        if not hasattr(self, 'root') or not self.root.winfo_exists():
            return

        self.center_window()
        try:
            self.root.iconbitmap('chat_icon.ico')
        except:
            pass
        self.root.mainloop()


if __name__ == "__main__":
    try:
        import sys
        import traceback
        from tkinter import messagebox

        gui = ChatGUI()
        # Only call run if the GUI was successfully initialized and username was provided
        if hasattr(gui, 'chat_client'):  # This means username was provided and GUI was initialized
            gui.run()
    except Exception as e:
        error_msg = f"Application failed to start:\n\n{str(e)}\n\nTraceback:\n{traceback.format_exc()}"
        try:
            messagebox.showerror("Fatal Error", error_msg)
        except:
            pass
        # Keep console open with error
        print("\nError occurred:")
        print(error_msg)
        input("\nPress Enter to exit...")