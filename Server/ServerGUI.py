import customtkinter as ctk
from customtkinter import CTkScrollableFrame
from datetime import datetime
import threading

from Server.server import ChatServer


class ModernServerGUI:
    def __init__(self, server):
        self.server = server

        # Theme and color settings
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Main window setup
        self.root = ctk.CTk()
        self.root.title("Secure Chat Server Dashboard")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Create main container
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(expand=True, fill="both", padx=10, pady=10)

        # Create layout
        self.create_header_frame()
        self.create_main_content()
        self.create_status_bar()

        # Start update thread
        self.update_thread = None

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_header_frame(self):
        header_frame = ctk.CTkFrame(self.main_container)
        header_frame.pack(fill="x", pady=(0, 10))

        # Server controls
        controls_frame = ctk.CTkFrame(header_frame)
        controls_frame.pack(side="left", padx=5)

        ctk.CTkLabel(controls_frame, text="Server IP:").pack(side="left", padx=5)
        self.host_entry = ctk.CTkEntry(controls_frame, width=120)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(side="left", padx=5)

        ctk.CTkLabel(controls_frame, text="Port:").pack(side="left", padx=5)
        self.port_entry = ctk.CTkEntry(controls_frame, width=80)
        self.port_entry.insert(0, "8080")
        self.port_entry.pack(side="left", padx=5)

        self.start_button = ctk.CTkButton(
            controls_frame,
            text="Start Server",
            command=self.start_server,
            fg_color="green"
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            controls_frame,
            text="Stop Server",
            command=self.stop_server,
            fg_color="red",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        # Server status
        status_frame = ctk.CTkFrame(header_frame)
        status_frame.pack(side="right", padx=5)

        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Server Status: Stopped",
            font=("Helvetica", 12, "bold")
        )
        self.status_label.pack(side="right", padx=5)

    def create_main_content(self):
        # Create tabview
        self.tabview = ctk.CTkTabview(self.main_container)
        self.tabview.pack(expand=True, fill="both", pady=5)

        # Server Log Tab
        log_tab = self.tabview.add("Server Log")

        log_controls = ctk.CTkFrame(log_tab)
        log_controls.pack(fill="x", pady=(5, 0))

        ctk.CTkButton(
            log_controls,
            text="Export Logs",
            command=self.export_logs,
            fg_color="blue"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            log_controls,
            text="Clear Logs",
            command=self.clear_logs,
            fg_color="red"
        ).pack(side="left", padx=5)

        self.text_widget = ctk.CTkTextbox(
            log_tab,
            wrap="word",
            font=("Consolas", 12)
        )
        self.text_widget.pack(expand=True, fill="both", padx=5, pady=5)

        # Clients Tab
        clients_tab = self.tabview.add("Connected Clients")

        clients_controls = ctk.CTkFrame(clients_tab)
        clients_controls.pack(fill="x", pady=(5, 0))

        ctk.CTkButton(
            clients_controls,
            text="Disconnect Selected",
            command=self.disconnect_selected_client,
            fg_color="red"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            clients_controls,
            text="Disconnect All",
            command=self.disconnect_all_clients,
            fg_color="red"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            clients_controls,
            text="Refresh List",
            command=self.update_client_list,
            fg_color="blue"
        ).pack(side="left", padx=5)

        # Clients list
        self.clients_frame = CTkScrollableFrame(clients_tab)
        self.clients_frame.pack(expand=True, fill="both", pady=5)

        # Headers
        self.create_list_headers(self.clients_frame, ["IP", "Port", "Connected Time", "Active Rooms"])

        # Rooms Tab
        rooms_tab = self.tabview.add("Chat Rooms")

        rooms_controls = ctk.CTkFrame(rooms_tab)
        rooms_controls.pack(fill="x", pady=(5, 0))

        ctk.CTkButton(
            rooms_controls,
            text="Close Selected Room",
            command=self.close_selected_room,
            fg_color="red"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            rooms_controls,
            text="Close All Rooms",
            command=self.close_all_rooms,
            fg_color="red"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            rooms_controls,
            text="Refresh Rooms",
            command=self.update_rooms_list,
            fg_color="blue"
        ).pack(side="left", padx=5)

        # Rooms list
        self.rooms_frame = CTkScrollableFrame(rooms_tab)
        self.rooms_frame.pack(expand=True, fill="both", pady=5)

        # Headers
        self.create_list_headers(self.rooms_frame, ["Room Name", "Active Users", "Messages"])

    def create_list_headers(self, parent, headers):
        header_frame = ctk.CTkFrame(parent)
        header_frame.pack(fill="x", padx=5, pady=5)

        for i, header in enumerate(headers):
            ctk.CTkLabel(
                header_frame,
                text=header,
                font=("Helvetica", 12, "bold")
            ).grid(row=0, column=i, padx=5, sticky="w")
            header_frame.grid_columnconfigure(i, weight=1)

    def create_status_bar(self):
        status_bar = ctk.CTkFrame(self.main_container)
        status_bar.pack(fill="x", side="bottom")

        self.connection_count = ctk.CTkLabel(
            status_bar,
            text="Connections: 0"
        )
        self.connection_count.pack(side="left", padx=5)

        self.message_count = ctk.CTkLabel(
            status_bar,
            text="Messages: 0"
        )
        self.message_count.pack(side="left", padx=5)

        self.uptime_label = ctk.CTkLabel(
            status_bar,
            text="Uptime: 0:00:00"
        )
        self.uptime_label.pack(side="right", padx=5)

    def update_status_bar(self):
        if self.server.is_running:
            self.connection_count.configure(
                text=f"Active Connections: {self.server.stats['active_connections']}"
            )
            self.message_count.configure(
                text=f"Total Messages: {self.server.stats['total_messages']}"
            )

            if self.server.stats["start_time"]:
                uptime = datetime.now() - self.server.stats["start_time"]
                hours = uptime.seconds // 3600
                minutes = (uptime.seconds % 3600) // 60
                seconds = uptime.seconds % 60
                self.uptime_label.configure(
                    text=f"Uptime: {hours}:{minutes:02d}:{seconds:02d}"
                )

            self.root.after(1000, self.update_status_bar)

    def start_server(self):
        host = self.host_entry.get()
        port = self.port_entry.get()

        if self.server.start(host, port):
            self.status_label.configure(text="Server Status: Running")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.host_entry.configure(state="disabled")
            self.port_entry.configure(state="disabled")
            self.update_status_bar()

            # Start update thread for lists
            self.update_thread = threading.Thread(target=self.update_lists, daemon=True)
            self.update_thread.start()

    def stop_server(self):
        if self.server.is_running:
            self.server.stop()
            self.status_label.configure(text="Server Status: Stopped")
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.host_entry.configure(state="normal")
            self.port_entry.configure(state="normal")

    def update_lists(self):
        while self.server.is_running:
            self.root.after(0, self.update_client_list)
            self.root.after(0, self.update_rooms_list)
            threading.Event().wait(1.0)  # Update every second

    def update_client_list(self):
        # Clear existing items
        for widget in self.clients_frame.winfo_children()[1:]:  # Skip headers
            widget.destroy()

        # Add current clients
        for client_socket, client_data in self.server.clients.items():
            ip, port = client_data["address"]
            connected_time = datetime.now() - client_data.get("connect_time", datetime.now())
            rooms = ", ".join(client_data["rooms"]) or "None"

            row_frame = ctk.CTkFrame(self.clients_frame)
            row_frame.pack(fill="x", padx=5, pady=2)

            ctk.CTkLabel(row_frame, text=ip).grid(row=0, column=0, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=str(port)).grid(row=0, column=1, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=str(connected_time).split(".")[0]).grid(row=0, column=2, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=rooms).grid(row=0, column=3, padx=5, sticky="w")

            for j in range(4):
                row_frame.grid_columnconfigure(j, weight=1)

    def update_rooms_list(self):
        # Clear existing items
        for widget in self.rooms_frame.winfo_children()[1:]:  # Skip headers
            widget.destroy()

        # Add current rooms
        for room_name, clients in self.server.rooms.items():
            row_frame = ctk.CTkFrame(self.rooms_frame)
            row_frame.pack(fill="x", padx=5, pady=2)

            ctk.CTkLabel(row_frame, text=room_name).grid(row=0, column=0, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text=str(len(clients))).grid(row=0, column=1, padx=5, sticky="w")
            ctk.CTkLabel(row_frame, text="N/A").grid(row=0, column=2, padx=5, sticky="w")

            for j in range(3):
                row_frame.grid_columnconfigure(j, weight=1)

    def disconnect_selected_client(self):
        # Implementation will depend on selection mechanism
        pass

    def disconnect_all_clients(self):
        if self.server.clients:
            for client_socket in list(self.server.clients.keys()):
                self.server.disconnect_client(client_socket)

    def close_selected_room(self):
        # Implementation will depend on selection mechanism
        pass

    def close_all_rooms(self):
        if self.server.rooms:
            for room_name in list(self.server.rooms.keys()):
                for client_socket in self.server.rooms[room_name][:]:
                    self.server.leave_room(client_socket, room_name)

    def clear_logs(self):
        self.text_widget.delete("1.0", "end")

    def export_logs(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"server_log_{timestamp}.txt"

        try:
            with open(filename, "w") as f:
                f.write(self.text_widget.get("1.0", "end"))
        except Exception as e:
            print(f"Error exporting logs: {e}")

    def log_message(self, message):
        self.text_widget.insert("end", message + "\n")
        self.text_widget.see("end")

    def on_closing(self):
        if self.server.is_running:
            self.stop_server()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# main.py
if __name__ == "__main__":
    server = ChatServer("127.0.0.1","8080")
    gui = ModernServerGUI(server)
    server.log_callback = gui.log_message
    gui.run()