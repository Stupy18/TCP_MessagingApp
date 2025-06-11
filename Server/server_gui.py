import traceback
import customtkinter as ctk
from tkinter import messagebox

from Server.functionality.chat_server import ChatServer
from Server.gui.components.headers import ServerHeader
from Server.gui.components.stats_cards import StatsCards
from Server.gui.styles import ServerThemeManager
from Server.gui.components.logs_tab import LogsTab
from Server.gui.components.clients_tab import ClientsTab
from Server.gui.components.rooms_tab import RoomsTab
from Server.gui.dialogs import ServerDialogs


class ModernServerGUI:
    """Main server GUI orchestrator using modular components"""

    def __init__(self):
        # Initialize theme manager
        self.theme_manager = ServerThemeManager()
        self.colors = self.theme_manager.get_colors()

        # Initialize main window
        self.root = ctk.CTk()
        self.root.title("SecureTransport Server Dashboard")
        self.root.geometry("1280x800")
        self.root.minsize(1000, 700)

        # Create server instance
        self.chat_server = ChatServer()

        # Initialize components
        self._initialize_components()

        # Create layout
        self._create_layout()

        # Setup timers and events
        self._setup_events()

    def _initialize_components(self):
        """Initialize all GUI components"""
        # Create main container
        self.main = ctk.CTkFrame(self.root, fg_color="transparent")

        # Initialize component sections
        self.header = ServerHeader(
            self.main,
            self.colors,
            self.start,
            self.stop
        )

        self.stats_cards = StatsCards(self.main, self.colors)

        # Tab components will be initialized when tabs are created
        self.logs_tab = None
        self.clients_tab = None
        self.rooms_tab = None

        # Dialog manager
        self.dialogs = ServerDialogs(self.colors)

    def _create_layout(self):
        """Create the main layout using components"""
        # Pack main container
        self.main.pack(expand=True, fill="both", padx=20, pady=20)

        # Create header
        self.header.create_header(self.chat_server.port)

        # Create stats cards
        self.stats_cards.create_stats_section()

        # Create tabs
        self._create_tabs()

        # Create status bar
        self._create_status_bar()

    def _create_tabs(self):
        """Create the tabview with all tabs"""
        self.tabview = ctk.CTkTabview(
            self.main,
            corner_radius=16,
            fg_color=self.colors["card"],
            segmented_button_fg_color=self.colors["background"],
            segmented_button_selected_color=self.colors["primary"],
            segmented_button_selected_hover_color=self.colors["hover_primary"]
        )
        self.tabview.pack(expand=True, fill="both")

        # Create tabs
        self.tabview.add("Logs")
        self.tabview.add("Connected Clients")
        self.tabview.add("Chat Rooms")

        # Set default tab
        self.tabview.set("Logs")

        # Initialize tab components
        self.logs_tab = LogsTab(self.tabview.tab("Logs"), self.colors)
        self.logs_tab.setup_logs_tab()

        # Set the log callback for the server
        self.chat_server = ChatServer(log_callback=self.logs_tab.update_text_widget)

        self.clients_tab = ClientsTab(
            self.tabview.tab("Connected Clients"),
            self.colors,
            self.disconnect_selected_client,
            self.disconnect_all_clients,
            self.update_client_list
        )
        self.clients_tab.setup_clients_tab()

        self.rooms_tab = RoomsTab(
            self.tabview.tab("Chat Rooms"),
            self.colors,
            self.close_selected_room,
            self.close_all_rooms,
            self.update_rooms_list
        )
        self.rooms_tab.setup_rooms_tab()

        # Initial updates
        self.update_client_list()
        self.update_rooms_list()

    def _create_status_bar(self):
        """Create the status bar at the bottom"""
        bar = ctk.CTkFrame(
            self.main,
            height=40,
            corner_radius=10,
            fg_color=self.colors["card"],
            border_color=self.colors["primary"],
            border_width=1
        )
        bar.pack(fill="x", pady=(16, 0))
        bar.pack_propagate(False)

        # Version info
        ctk.CTkLabel(
            bar,
            text="SecureTransport Server v1.0",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"]
        ).pack(side="left", padx=15)

        # Server info button
        server_info_button = ctk.CTkButton(
            bar,
            text="Server Info",
            command=self.show_server_info,
            fg_color="transparent",
            text_color=self.colors["primary"],
            hover_color="#333333",
            width=100,
            height=30
        )
        server_info_button.pack(side="right", padx=15)

    def _setup_events(self):
        """Setup update timers and window events"""
        # Setup update timer
        self.root.after(1000, self.update_stats)

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def start(self):
        """Start the server"""
        try:
            config = self.header.get_server_config()
            host = config["host"]
            port = config["port"]

            success, msg = self.chat_server.start(host, port)

            if success:
                self.header.update_controls_state(True)
            else:
                messagebox.showerror("Error", msg)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def stop(self):
        """Stop the server"""
        if messagebox.askyesno("Stop Server", "Are you sure you want to stop the server?"):
            success, msg = self.chat_server.stop()

            if success:
                self.header.update_controls_state(False)
                self.stats_cards.reset_stats()
            else:
                messagebox.showerror("Error", msg)

    def update_stats(self):
        """Update statistics display"""
        stats = self.chat_server.get_stats()
        self.stats_cards.update_stats(stats)
        self.root.after(1000, self.update_stats)

    def update_client_list(self):
        """Update the client list display"""
        client_list = self.chat_server.get_client_list()
        self.clients_tab.update_client_list(client_list)

    def update_rooms_list(self):
        """Update the room list display"""
        room_list = self.chat_server.get_room_list()
        self.rooms_tab.update_rooms_list(room_list)

    def disconnect_selected_client(self):
        """Disconnect selected clients"""
        selected = self.clients_tab.get_selected_clients()

        if not selected:
            messagebox.showwarning("Warning", "Please select a client to disconnect")
            return

        if messagebox.askyesno("Confirm Disconnect", "Are you sure you want to disconnect the selected client(s)?"):
            for frame in selected:
                client_data = frame.data
                ip, port = client_data["ip"], client_data["port"]
                self.chat_server.disconnect_client_by_address(ip, port)

            self.update_client_list()

    def disconnect_all_clients(self):
        """Disconnect all clients"""
        clients = self.chat_server.get_client_list()
        if not clients:
            messagebox.showinfo("Info", "No clients connected")
            return

        if messagebox.askyesno("Confirm Disconnect All", "Are you sure you want to disconnect all clients?"):
            current_host = self.chat_server.host
            current_port = self.chat_server.port

            if self.chat_server.is_running:
                self.chat_server.stop()
                self.chat_server.start(current_host, current_port)

            self.update_client_list()

    def close_selected_room(self):
        """Close selected rooms"""
        selected = self.rooms_tab.get_selected_rooms()

        if not selected:
            messagebox.showwarning("Warning", "Please select a room to close")
            return

        if messagebox.askyesno("Confirm Close Room", "Are you sure you want to close the selected room(s)?"):
            for frame in selected:
                room_data = frame.data
                room_name = room_data["name"]
                self.chat_server.close_room(room_name)

            self.update_rooms_list()

    def close_all_rooms(self):
        """Close all rooms"""
        rooms = self.chat_server.get_room_list()
        if not rooms:
            messagebox.showinfo("Info", "No active rooms")
            return

        if messagebox.askyesno("Confirm Close All", "Are you sure you want to close all rooms?"):
            for room in rooms:
                self.chat_server.close_room(room["name"])

            self.update_rooms_list()

    def show_server_info(self):
        """Show server information dialog"""
        stats = self.chat_server.get_stats()
        self.dialogs.show_server_info(self.root, stats)

    def on_close(self):
        """Handle window close event"""
        if self.chat_server.is_running:
            if messagebox.askyesno("Confirm Exit", "Server is running. Are you sure you want to quit?"):
                self.chat_server.stop()
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        """Start the GUI main loop"""
        self.root.mainloop()


if __name__ == "__main__":
    try:
        app = ModernServerGUI()
        app.run()
    except Exception as e:
        print("Error starting application:", str(e))
        print(traceback.format_exc())
        input("Press Enter to exit...")