import traceback
import customtkinter as ctk
from tkinter import messagebox, scrolledtext
from datetime import datetime
import threading
import time
from ChatServer import ChatServer


class ModernServerGUI:
    def __init__(self):
        # Set appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Create server instance
        self.chat_server = ChatServer(log_callback=self.update_text_widget)

        # Main window setup
        self.root = ctk.CTk()
        self.root.title("Encryptify Server Dashboard")
        self.root.geometry("1280x800")
        self.root.minsize(1000, 700)

        # Define color palette
        self.colors = {
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

        # Create main container with padding
        self.main = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main.pack(expand=True, fill="both", padx=20, pady=20)

        # Create layout components
        self.build_header()
        self.build_stats()
        self.build_tabs()
        self.build_status()

        # Setup update timer
        self.root.after(1000, self.update_stats)

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_header(self):
        header = ctk.CTkFrame(
            self.main,
            corner_radius=16,
            fg_color=self.colors["card"],
            border_width=1,
            border_color=self.colors["primary"]
        )
        header.pack(fill="x", pady=(0, 16))

        title = ctk.CTkLabel(
            header,
            text="Secure Chat Server",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(side="left", padx=20, pady=12)

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.pack(side="right", padx=20)

        self.host_entry = ctk.CTkEntry(controls, width=160, placeholder_text="Server IP")
        self.host_entry.insert(0, "0.0.0.0")
        self.host_entry.pack(side="left", padx=5)

        self.port_entry = ctk.CTkEntry(controls, width=80, placeholder_text="Port")
        self.port_entry.insert(0, str(self.chat_server.port))
        self.port_entry.pack(side="left", padx=5)

        self.start_button = ctk.CTkButton(
            controls,
            text="▶ Start",
            command=self.start,
            fg_color=self.colors["primary"],
            hover_color=self.colors["hover_primary"]
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            controls,
            text="■ Stop",
            command=self.stop,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

    def build_stats(self):
        stats = ctk.CTkFrame(self.main, fg_color="transparent")
        stats.pack(fill="x", pady=(0, 16))

        self.conn_card = self.create_stat_card(stats, "Connections", "0", self.colors["primary"])
        self.msg_card = self.create_stat_card(stats, "Messages", "0", self.colors["accent"])
        self.room_card = self.create_stat_card(stats, "Rooms", "0", self.colors["success"])
        self.uptime_card = self.create_stat_card(stats, "Uptime", "0:00:00", self.colors["warning"])

    def create_stat_card(self, parent, title, value, color):
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

    def build_tabs(self):
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

        # Logs Tab
        self.setup_logs_tab()

        # Clients Tab
        self.setup_clients_tab()

        # Rooms Tab
        self.setup_rooms_tab()

        # Initialize client and room lists
        self.client_frames = []
        self.client_data = []
        self.room_frames = []
        self.room_data = []

        # Initial updates
        self.update_client_list()
        self.update_rooms_list()

    def setup_logs_tab(self):
        log_frame = self.tabview.tab("Logs")

        # Log controls
        button_frame = ctk.CTkFrame(log_frame, fg_color="transparent")
        button_frame.pack(pady=10)

        export_btn = ctk.CTkButton(
            button_frame,
            text="📁 Export Logs",
            command=self.export_logs,
            fg_color=self.colors["primary"],
            hover_color=self.colors["hover_primary"]
        )
        export_btn.pack(side="left", padx=10)

        clear_btn = ctk.CTkButton(
            button_frame,
            text="🗑 Clear Logs",
            command=self.clear_logs,
            fg_color=self.colors["danger"],
            hover_color="#c62f3b"
        )
        clear_btn.pack(side="left", padx=10)

        # Log text widget
        self.text_widget = scrolledtext.ScrolledText(
            log_frame,
            wrap="word",
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#e0e0e0",
            insertbackground="#e0e0e0",
            borderwidth=0
        )
        self.text_widget.pack(expand=True, fill="both", padx=10, pady=10)

    def setup_clients_tab(self):
        clients_frame = self.tabview.tab("Connected Clients")

        # Client controls
        client_controls = ctk.CTkFrame(clients_frame, fg_color="transparent")
        client_controls.pack(fill="x", pady=10)

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
            hover_color=self.colors["hover_primary"],
            width=100
        )
        refresh_clients.pack(side="left", padx=5)

        # Client list container
        client_list_frame = ctk.CTkFrame(clients_frame, fg_color="#1e1e1e", corner_radius=6)
        client_list_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Headers
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

        # Scrollable frame for client items
        self.clients_scrollable = ctk.CTkScrollableFrame(
            client_list_frame,
            fg_color="#1e1e1e",
            corner_radius=0
        )
        self.clients_scrollable.pack(expand=True, fill="both", padx=2, pady=(0, 2))

    def setup_rooms_tab(self):
        rooms_frame = self.tabview.tab("Chat Rooms")

        # Room controls
        room_controls = ctk.CTkFrame(rooms_frame, fg_color="transparent")
        room_controls.pack(fill="x", pady=10)

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
            hover_color=self.colors["hover_primary"],
            width=100
        )
        refresh_rooms.pack(side="left", padx=5)

        # Room list frame
        room_list_frame = ctk.CTkFrame(rooms_frame, fg_color="#1e1e1e", corner_radius=6)
        room_list_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Headers
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

        # Scrollable frame for room items
        self.rooms_scrollable = ctk.CTkScrollableFrame(
            room_list_frame,
            fg_color="#1e1e1e",
            corner_radius=0
        )
        self.rooms_scrollable.pack(expand=True, fill="both", padx=2, pady=(0, 2))

    def build_status(self):
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
            text="Encryptify Server v1.0",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"]
        ).pack(side="left", padx=15)

        # Server info button
        self.server_info_button = ctk.CTkButton(
            bar,
            text="Server Info",
            command=self.show_server_info,
            fg_color="transparent",
            text_color=self.colors["primary"],
            hover_color="#333333",
            width=100,
            height=30
        )
        self.server_info_button.pack(side="right", padx=15)

    def update_stats(self):
        stats = self.chat_server.get_stats()

        if stats["running"]:
            self.conn_card.configure(text=str(stats["active_connections"]))
            self.msg_card.configure(text=str(stats["total_messages"]))
            self.room_card.configure(text=str(stats["active_rooms"]))

            if stats["uptime"]:
                seconds = stats["uptime"].seconds
                uptime_str = f"{seconds // 3600}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"
                self.uptime_card.configure(text=uptime_str)

        self.root.after(1000, self.update_stats)

    def update_text_widget(self, message):
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", message + "\n")
        self.text_widget.configure(state="disabled")
        self.text_widget.see("end")

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

        # Create an info dialog
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

    def start(self):
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())

            success, msg = self.chat_server.start(host, port)

            if success:
                self.start_button.configure(state="disabled")
                self.stop_button.configure(state="normal")
                self.host_entry.configure(state="disabled")
                self.port_entry.configure(state="disabled")
            else:
                messagebox.showerror("Error", msg)

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_text_widget(f"Failed to start server: {str(e)}")


    def stop(self):
        if messagebox.askyesno("Stop Server", "Are you sure you want to stop the server?"):
            success, msg = self.chat_server.stop()

            if success:
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.host_entry.configure(state="normal")
                self.port_entry.configure(state="normal")

                # Reset stat cards
                self.conn_card.configure(text="0")
                self.msg_card.configure(text="0")
                self.room_card.configure(text="0")
                self.uptime_card.configure(text="0:00:00")
            else:
                messagebox.showerror("Error", msg)

    def on_close(self):
        if self.chat_server.is_running:
            if messagebox.askyesno("Confirm Exit", "Server is running. Are you sure you want to quit?"):
                self.chat_server.stop()
                self.root.destroy()
        else:
            self.root.destroy()

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


