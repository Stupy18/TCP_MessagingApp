import traceback

import customtkinter as ctk
from tkinter import messagebox, scrolledtext
import threading
from datetime import datetime
import time
from PIL import Image, ImageTk

from ChatServer import ChatServer


class ModernServerGUI:
    def __init__(self):
        # Set appearance
        ctk.set_appearance_mode("dark")  # Modes: "System", "Dark", "Light"
        ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"

        # Create server instance
        self.chat_server = ChatServer(log_callback=self.update_text_widget)

        # Main window setup
        self.root = ctk.CTk()
        self.root.title("Secure Chat Server Dashboard")
        self.root.geometry("1280x800")
        self.root.minsize(1000, 700)

        # Define color palette
        self.colors = {
            "primary": "#3a7ebf",  # Primary blue
            "primary_hover": "#2b5d8b",  # Darker blue
            "accent": "#7e3abf",  # Purple accent
            "success": "#2D9D78",  # Green
            "warning": "#e6b422",  # Yellow
            "danger": "#e63946",  # Red
            "background": "#1e1e1e",  # Dark background
            "card": "#2a2a2a",  # Slightly lighter than background
            "text": "#ffffff",  # White text
            "text_secondary": "#a0a0a0"  # Gray text
        }

        # Create main container with padding
        self.main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_container.pack(expand=True, fill="both", padx=15, pady=15)

        # Create layout
        self.create_header_frame()
        self.create_main_content()
        self.create_status_bar()

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.handle_close)

        # Setup update timer
        self.root.after(1000, self.update_status_bar)

        # Create server statistics cards
        self.create_statistics_cards()

    def handle_close(self):
        if self.chat_server.is_running:
            # Create custom confirmation dialog
            confirm_dialog = ctk.CTkToplevel(self.root)
            confirm_dialog.title("Confirm Exit")
            confirm_dialog.geometry("400x200")
            confirm_dialog.resizable(False, False)
            confirm_dialog.transient(self.root)
            confirm_dialog.grab_set()

            # Center the dialog
            confirm_dialog.update_idletasks()
            width = confirm_dialog.winfo_width()
            height = confirm_dialog.winfo_height()
            x = (confirm_dialog.winfo_screenwidth() // 2) - (width // 2)
            y = (confirm_dialog.winfo_screenheight() // 2) - (height // 2)
            confirm_dialog.geometry(f'+{x}+{y}')

            # Set layout
            confirm_dialog.grid_columnconfigure(0, weight=1)

            # Warning icon and text
            warning_frame = ctk.CTkFrame(confirm_dialog, fg_color="transparent")
            warning_frame.grid(row=0, column=0, pady=(20, 0), sticky="ew")

            warning_icon = ctk.CTkLabel(
                warning_frame,
                text="⚠️",
                font=ctk.CTkFont(size=24),
                text_color=self.colors["warning"]
            )
            warning_icon.pack(side="left", padx=(20, 10))

            warning_text = ctk.CTkLabel(
                warning_frame,
                text="Server is currently running",
                font=ctk.CTkFont(size=16, weight="bold")
            )
            warning_text.pack(side="left")

            # Message
            message = ctk.CTkLabel(
                confirm_dialog,
                text="Are you sure you want to stop the server and quit?",
                wraplength=350
            )
            message.grid(row=1, column=0, pady=(15, 20), padx=20)

            # Buttons
            button_frame = ctk.CTkFrame(confirm_dialog, fg_color="transparent")
            button_frame.grid(row=2, column=0, pady=(0, 20))

            cancel_button = ctk.CTkButton(
                button_frame,
                text="Cancel",
                command=confirm_dialog.destroy,
                fg_color=self.colors["card"],
                hover_color="#3a3a3a",
                border_width=1,
                border_color="#555555",
                width=100
            )
            cancel_button.pack(side="left", padx=10)

            def confirm_exit():
                self.chat_server.stop()
                self.root.destroy()

            confirm_button = ctk.CTkButton(
                button_frame,
                text="Stop & Quit",
                command=confirm_exit,
                fg_color=self.colors["danger"],
                hover_color="#c62f3b",
                width=100
            )
            confirm_button.pack(side="left", padx=10)
        else:
            self.root.destroy()

    def create_header_frame(self):
        header_frame = ctk.CTkFrame(
            self.main_container,
            corner_radius=10,
            fg_color=self.colors["card"],
            border_width=1,
            border_color=self.colors["primary"]
        )
        header_frame.pack(fill="x", pady=(0, 15))

        # Server controls
        controls_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.pack(side="left", padx=20, pady=15)

        # Server connection settings
        connection_label = ctk.CTkLabel(
            controls_frame,
            text="Server Configuration",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        connection_label.pack(anchor="w", pady=(0, 10))

        # Create a grid layout for inputs
        input_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        input_frame.pack(fill="x")

        # IP input
        ctk.CTkLabel(input_frame, text="Server IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.host_entry = ctk.CTkEntry(input_frame, width=150)
        self.host_entry.insert(0, "0.0.0.0")
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)

        # Port input
        ctk.CTkLabel(input_frame, text="Port:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.port_entry = ctk.CTkEntry(input_frame, width=80)
        self.port_entry.insert(0, str(self.chat_server.port))
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)

        # Control buttons
        button_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=(15, 0))

        self.start_button = ctk.CTkButton(
            button_frame,
            text="Start Server",
            command=self.start,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"]
        )
        self.start_button.pack(side="left", padx=(0, 10))

        self.stop_button = ctk.CTkButton(
            button_frame,
            text="Stop Server",
            command=self.stop,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            state="disabled"
        )
        self.stop_button.pack(side="left")

        # Server status
        status_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        status_frame.pack(side="right", padx=20)

        self.status_indicator = ctk.CTkLabel(
            status_frame,
            text="●",
            font=ctk.CTkFont(size=24),
            text_color="#666666"  # Gray for stopped
        )
        self.status_indicator.pack(side="left", padx=(0, 5))

        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Server Status: Stopped",
            font=ctk.CTkFont(size=16)
        )
        self.status_label.pack(side="left", padx=5)

    def create_statistics_cards(self):
        # Create frame for statistics cards
        stats_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 15))

        # Create card frames
        conn_card = self.create_card(stats_frame, "Active Connections", "0", self.colors["primary"])
        msg_card = self.create_card(stats_frame, "Total Messages", "0", self.colors["accent"])
        room_card = self.create_card(stats_frame, "Active Rooms", "0", self.colors["success"])
        uptime_card = self.create_card(stats_frame, "Uptime", "0:00:00", self.colors["warning"])

        # Store the value labels directly as instance variables
        self.connection_card = conn_card
        self.message_card = msg_card
        self.room_card = room_card
        self.uptime_card = uptime_card

    def create_card(self, parent, title, value, color):
        # Create card frame
        card = ctk.CTkFrame(
            parent,
            corner_radius=10,
            fg_color=self.colors["card"],
            border_width=1,
            border_color=color
        )
        card.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        # Add colored top strip
        strip = ctk.CTkFrame(
            card,
            height=5,
            corner_radius=0,
            fg_color=color
        )
        strip.pack(fill="x", pady=(0, 5))

        # Add title
        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"]
        ).pack(pady=(5, 2), padx=15, anchor="w")

        # Create and add value label
        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=20, weight="bold")
        )
        value_label.pack(pady=(0, 15), padx=15, anchor="w")

        return value_label

    def _create_stat_card(self, parent, title, value, color, width_fraction):
        # Create card frame
        card = ctk.CTkFrame(
            parent,
            corner_radius=10,
            fg_color=self.colors["card"],
            border_width=1,
            border_color=color
        )
        card.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        # Add colored top strip
        strip = ctk.CTkFrame(
            card,
            height=5,
            corner_radius=0,
            fg_color=color
        )
        strip.pack(fill="x", pady=(0, 5))

        # Add title
        title_label = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"]
        )
        title_label.pack(pady=(5, 2), padx=15, anchor="w")

        # Add value
        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=20, weight="bold")
        )
        value_label.pack(pady=(0, 15), padx=15, anchor="w")

        return value_label

    def create_main_content(self):
        # Create tabview for content
        self.tabview = ctk.CTkTabview(
            self.main_container,
            corner_radius=10,
            fg_color=self.colors["card"],
            segmented_button_fg_color=self.colors["background"],
            segmented_button_selected_color=self.colors["primary"],
            segmented_button_selected_hover_color=self.colors["primary_hover"],
            segmented_button_unselected_hover_color="#3a3a3a"
        )
        self.tabview.pack(expand=True, fill="both", pady=(0, 15))

        # Create tabs
        self.tabview.add("Server Log")
        self.tabview.add("Connected Clients")
        self.tabview.add("Chat Rooms")

        # Set default tab
        self.tabview.set("Server Log")

        # Server Log Tab
        log_frame = self.tabview.tab("Server Log")

        # Log controls
        log_controls = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_controls.pack(fill="x", pady=(10, 15))

        export_button = ctk.CTkButton(
            log_controls,
            text="Export Logs",
            command=self.export_logs,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            width=120
        )
        export_button.pack(side="left", padx=5)

        clear_button = ctk.CTkButton(
            log_controls,
            text="Clear Logs",
            command=self.clear_logs,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=120
        )
        clear_button.pack(side="left", padx=5)

        # Log text widget (using standard scrolledtext as CTk doesn't have a direct equivalent)
        log_container = ctk.CTkFrame(log_frame, fg_color="#1e1e1e", corner_radius=6)
        log_container.pack(expand=True, fill="both", padx=10, pady=(0, 10))

        self.text_widget = scrolledtext.ScrolledText(
            log_container,
            wrap="word",
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#e0e0e0",
            insertbackground="#e0e0e0",
            selectbackground=self.colors["primary"],
            borderwidth=0,
            highlightthickness=0
        )
        self.text_widget.pack(expand=True, fill="both", padx=2, pady=2)

        # Clients Tab
        clients_frame = self.tabview.tab("Connected Clients")

        # Client controls
        client_controls = ctk.CTkFrame(clients_frame, fg_color="transparent")
        client_controls.pack(fill="x", pady=(10, 15))

        disconnect_selected = ctk.CTkButton(
            client_controls,
            text="Disconnect Selected",
            command=self.disconnect_selected_client,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=160
        )
        disconnect_selected.pack(side="left", padx=5)

        disconnect_all = ctk.CTkButton(
            client_controls,
            text="Disconnect All",
            command=self.disconnect_all_clients,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=120
        )
        disconnect_all.pack(side="left", padx=5)

        refresh_clients = ctk.CTkButton(
            client_controls,
            text="↻ Refresh",
            command=self.update_client_list,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            width=100
        )
        refresh_clients.pack(side="left", padx=5)

        # Client list (using custom tree implementation)
        client_list_frame = ctk.CTkFrame(clients_frame, fg_color="#1e1e1e", corner_radius=6)
        client_list_frame.pack(expand=True, fill="both", padx=10, pady=(0, 10))

        # Tree headers
        headers_frame = ctk.CTkFrame(client_list_frame, fg_color="#2a2a2a", height=30)
        headers_frame.pack(fill="x", padx=2, pady=(2, 0))
        headers_frame.pack_propagate(False)

        header_texts = ["IP", "Port", "Connected Time", "Active Rooms"]
        for i, text in enumerate(header_texts):
            width = 150 if i < 3 else 300  # Make the Rooms column wider
            header = ctk.CTkLabel(
                headers_frame,
                text=text,
                font=ctk.CTkFont(weight="bold", size=12),
                width=width
            )
            header.pack(side="left", padx=5)

        # Create scrollable frame for client items
        self.clients_scrollable = ctk.CTkScrollableFrame(
            client_list_frame,
            fg_color="#1e1e1e",
            corner_radius=0
        )
        self.clients_scrollable.pack(expand=True, fill="both", padx=2, pady=(0, 2))

        # Rooms Tab
        rooms_frame = self.tabview.tab("Chat Rooms")

        # Room controls
        room_controls = ctk.CTkFrame(rooms_frame, fg_color="transparent")
        room_controls.pack(fill="x", pady=(10, 15))

        close_selected = ctk.CTkButton(
            room_controls,
            text="Close Selected Room",
            command=self.close_selected_room,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=160
        )
        close_selected.pack(side="left", padx=5)

        close_all = ctk.CTkButton(
            room_controls,
            text="Close All Rooms",
            command=self.close_all_rooms,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            width=120
        )
        close_all.pack(side="left", padx=5)

        refresh_rooms = ctk.CTkButton(
            room_controls,
            text="↻ Refresh",
            command=self.update_rooms_list,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            width=100
        )
        refresh_rooms.pack(side="left", padx=5)

        # Room list (using custom implementation)
        room_list_frame = ctk.CTkFrame(rooms_frame, fg_color="#1e1e1e", corner_radius=6)
        room_list_frame.pack(expand=True, fill="both", padx=10, pady=(0, 10))

        # Tree headers
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

        # Create scrollable frame for room items
        self.rooms_scrollable = ctk.CTkScrollableFrame(
            room_list_frame,
            fg_color="#1e1e1e",
            corner_radius=0
        )
        self.rooms_scrollable.pack(expand=True, fill="both", padx=2, pady=(0, 2))

        # Initialize client and room lists
        self.client_frames = []
        self.client_data = []
        self.room_frames = []
        self.room_data = []

        # Initial updates
        self.update_client_list()
        self.update_rooms_list()

    def create_client_item(self, client_data):
        # Create a frame for this client item
        item_frame = ctk.CTkFrame(self.clients_scrollable, fg_color="#232323", height=40, corner_radius=6)
        item_frame.pack(fill="x", padx=5, pady=3)
        item_frame.pack_propagate(False)

        # Store data for selection
        item_frame.data = client_data

        # Add client data to frame
        ip_label = ctk.CTkLabel(item_frame, text=client_data["ip"], width=150)
        ip_label.pack(side="left", padx=5)

        port_label = ctk.CTkLabel(item_frame, text=client_data["port"], width=150)
        port_label.pack(side="left", padx=5)

        time_label = ctk.CTkLabel(item_frame, text=client_data["connected_time"], width=150)
        time_label.pack(side="left", padx=5)

        rooms_text = ", ".join(client_data["rooms"]) or "None"
        rooms_label = ctk.CTkLabel(item_frame, text=rooms_text, width=300)
        rooms_label.pack(side="left", padx=5)

        # Add selection behavior
        def on_click(event):
            self.select_client_item(item_frame)

        item_frame.bind("<Button-1>", on_click)
        for widget in item_frame.winfo_children():
            widget.bind("<Button-1>", on_click)

        return item_frame

    def select_client_item(self, item_frame):
        # Toggle selection
        if hasattr(item_frame, "selected") and item_frame.selected:
            item_frame.configure(fg_color="#232323")
            item_frame.selected = False
        else:
            item_frame.configure(fg_color=self.colors["primary"])
            item_frame.selected = True

    def create_room_item(self, room_data):
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
        # Toggle selection
        if hasattr(item_frame, "selected") and item_frame.selected:
            item_frame.configure(fg_color="#232323")
            item_frame.selected = False
        else:
            item_frame.configure(fg_color=self.colors["primary"])
            item_frame.selected = True

    def create_status_bar(self):
        self.status_bar = ctk.CTkFrame(
            self.main_container,
            corner_radius=10,
            height=40,
            fg_color=self.colors["card"],
            border_width=1,
            border_color=self.colors["primary"]
        )
        self.status_bar.pack(fill="x")
        self.status_bar.pack_propagate(False)

        version_label = ctk.CTkLabel(
            self.status_bar,
            text="Encryptify Server v1.0",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"]
        )
        version_label.pack(side="left", padx=15)

        # Create a right-aligned frame for other status info
        right_status = ctk.CTkFrame(self.status_bar, fg_color="transparent")
        right_status.pack(side="right", fill="y")

        # Fill with content
        self.server_info_button = ctk.CTkButton(
            right_status,
            text="Server Info",
            command=self.show_server_info,
            fg_color="transparent",
            text_color=self.colors["primary"],
            hover_color="#333333",
            width=100,
            height=30
        )
        self.server_info_button.pack(side="right", padx=15)

    def update_status_bar(self):
        stats = self.chat_server.get_stats()

        if stats["running"]:
            # Print for debugging
            print(f"Stats: {stats}")

            # Directly update the labels
            self.connection_card.configure(text=str(stats["active_connections"]))
            self.message_card.configure(text=str(stats["total_messages"]))
            self.room_card.configure(text=str(stats["active_rooms"]))

            if stats["uptime"]:
                hours = stats["uptime"].seconds // 3600
                minutes = (stats["uptime"].seconds % 3600) // 60
                seconds = stats["uptime"].seconds % 60
                uptime_str = f"{hours}:{minutes:02d}:{seconds:02d}"
                self.uptime_card.configure(text=uptime_str)

        # Call again in 1 second
        self.root.after(1000, self.update_status_bar)

    def start(self):
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())

            success, message = self.chat_server.start(host, port)

            if success:
                self.status_label.configure(text="Server Status: Running")
                self.status_indicator.configure(text_color=self.colors["success"])  # Green for running
                self.start_button.configure(state="disabled")
                self.stop_button.configure(state="normal")
                self.host_entry.configure(state="disabled")
                self.port_entry.configure(state="disabled")
            else:
                messagebox.showerror("Error", message)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
            self.update_text_widget(f"Failed to start server: {str(e)}\n")

    def stop(self):
        if messagebox.askyesno("Confirm Stop", "Are you sure you want to stop the server?"):
            success, message = self.chat_server.stop()

            if success:
                self.status_label.configure(text="Server Status: Stopped")
                self.status_indicator.configure(text_color="#666666")  # Gray for stopped
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.host_entry.configure(state="normal")
                self.port_entry.configure(state="normal")

                # Reset stat cards
                self.connection_card.configure(text="0")
                self.message_card.configure(text="0")
                self.room_card.configure(text="0")
                self.uptime_card.configure(text="0:00:00")
            else:
                messagebox.showerror("Error", message)

    def update_text_widget(self, message):
        # This method is used as a callback for the server's log_callback
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", message + "\n")
        self.text_widget.configure(state="disabled")
        self.text_widget.see("end")

    def update_client_list(self):
        # Clear existing items
        for frame in self.client_frames:
            frame.destroy()
        self.client_frames = []

        # Get client list from server
        client_list = self.chat_server.get_client_list()
        self.client_data = client_list

        # Create new items
        for client in client_list:
            client_frame = self.create_client_item(client)
            self.client_frames.append(client_frame)

    def update_rooms_list(self):
        # Clear existing items
        for frame in self.room_frames:
            frame.destroy()
        self.room_frames = []

        # Get room list from server
        room_list = self.chat_server.get_room_list()
        self.room_data = room_list

        # Create new items
        for room in room_list:
            room_frame = self.create_room_item(room)
            self.room_frames.append(room_frame)

    def disconnect_selected_client(self):
        # Find selected client frames
        selected = [frame for frame in self.client_frames if hasattr(frame, "selected") and frame.selected]

        if not selected:
            messagebox.showwarning("Warning", "Please select a client to disconnect")
            return

        if messagebox.askyesno("Confirm Disconnect", "Are you sure you want to disconnect the selected client(s)?"):
            for frame in selected:
                client_data = frame.data
                ip, port = client_data["ip"], client_data["port"]
                # Disconnect the client using the server method
                self.chat_server.disconnect_client_by_address(ip, port)

            # Update the client list
            self.update_client_list()

    def disconnect_all_clients(self):
        clients = self.chat_server.get_client_list()
        if not clients:
            messagebox.showinfo("Info", "No clients connected")
            return

        if messagebox.askyesno("Confirm Disconnect All", "Are you sure you want to disconnect all clients?"):
            # Use stop and start to disconnect all clients
            current_host = self.chat_server.host
            current_port = self.chat_server.port

            if self.chat_server.is_running:
                self.chat_server.stop()
                self.chat_server.start(current_host, current_port)

            # Update the client list
            self.update_client_list()

    def close_selected_room(self):
        # Find selected room frames
        selected = [frame for frame in self.room_frames if hasattr(frame, "selected") and frame.selected]

        if not selected:
            messagebox.showwarning("Warning", "Please select a room to close")
            return

        if messagebox.askyesno("Confirm Close Room", "Are you sure you want to close the selected room(s)?"):
            for frame in selected:
                room_data = frame.data
                room_name = room_data["name"]
                # Close the room using the server method
                self.chat_server.close_room(room_name)

            # Update the room list
            self.update_rooms_list()

    def close_all_rooms(self):
        rooms = self.chat_server.get_room_list()
        if not rooms:
            messagebox.showinfo("Info", "No active rooms")
            return

        if messagebox.askyesno("Confirm Close All", "Are you sure you want to close all rooms?"):
            # Close each room using the server method
            for room in rooms:
                self.chat_server.close_room(room["name"])

            # Update the room list
            self.update_rooms_list()

    def clear_logs(self):
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear the logs?"):
            self.text_widget.configure(state="normal")
            self.text_widget.delete(1.0, "end")
            self.text_widget.configure(state="disabled")

    def export_logs(self):
        """Export server logs to a file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"server_log_{timestamp}.txt"

            with open(filename, "w") as f:
                f.write(self.text_widget.get(1.0, "end"))

            messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {str(e)}")

    def show_server_info(self):
        """Display server information and statistics"""
        stats = self.chat_server.get_stats()

        uptime_str = "0:00:00"
        if stats["uptime"]:
            hours = stats["uptime"].seconds // 3600
            minutes = (stats["uptime"].seconds % 3600) // 60
            seconds = stats["uptime"].seconds % 60
            uptime_str = f"{hours}:{minutes:02d}:{seconds:02d}"

        # Create an info dialog instead of a messagebox
        info_dialog = ctk.CTkToplevel(self.root)
        info_dialog.title("Server Information")
        info_dialog.geometry("500x350")
        info_dialog.resizable(False, False)
        info_dialog.transient(self.root)
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
            hover_color=self.colors["primary_hover"],
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

    def run(self):
        # Start the main event loop
        self.root.mainloop()

if __name__ == "__main__":
    try:
        app = ModernServerGUI()
        app.run()
    except Exception as e:
        print("Error starting application:", str(e))
        print(traceback.format_exc())
        input("Press Enter to exit...")