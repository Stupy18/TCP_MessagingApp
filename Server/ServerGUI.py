import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from datetime import datetime
import time

from ChatServer import ChatServer


class ServerGUI:
    def __init__(self):
        # Create server instance
        self.chat_server = ChatServer(log_callback=self.update_text_widget)

        # Main window setup
        self.root = tk.Tk()
        self.root.title("Secure Chat Server Dashboard")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Configure style
        self.setup_styles()

        # Create main container
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.pack(expand=True, fill=tk.BOTH)

        # Create layout
        self.create_header_frame()
        self.create_main_content()
        self.create_status_bar()

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Setup update timer
        self.root.after(1000, self.update_status_bar)

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Define colors
        self.colors = {
            "primary": "#1a237e",  # Deep blue
            "secondary": "#283593",
            "accent": "#3949ab",
            "success": "#43a047",
            "warning": "#fdd835",
            "danger": "#e53935",
            "text": "#ffffff",
            "text_dark": "#212121",
            "background": "#f5f5f5"
        }

        # Configure styles
        self.style.configure("Header.TFrame", background=self.colors["primary"])
        self.style.configure("Main.TFrame", background=self.colors["background"])
        self.style.configure("Status.TFrame", background=self.colors["primary"])

        self.style.configure("Header.TLabel",
                             background=self.colors["primary"],
                             foreground=self.colors["text"],
                             font=("Helvetica", 12, "bold"))

        self.style.configure("Status.TLabel",
                             background=self.colors["primary"],
                             foreground=self.colors["text"],
                             font=("Helvetica", 9))

        # Button styles
        self.style.configure("Control.TButton",
                             font=("Helvetica", 10),
                             padding=5)

        self.style.configure("Action.TButton",
                             font=("Helvetica", 10),
                             padding=5)

        self.style.configure("Danger.TButton",
                             font=("Helvetica", 10),
                             padding=5)

        self.style.map("Control.TButton",
                       background=[("active", self.colors["accent"]),
                                   ("disabled", self.colors["secondary"])],
                       foreground=[("active", self.colors["text"]),
                                   ("disabled", self.colors["text"])])

        self.style.map("Action.TButton",
                       background=[("active", self.colors["success"]),
                                   ("disabled", self.colors["secondary"])],
                       foreground=[("active", self.colors["text"]),
                                   ("disabled", self.colors["text"])])

        self.style.map("Danger.TButton",
                       background=[("active", self.colors["danger"]),
                                   ("disabled", self.colors["secondary"])],
                       foreground=[("active", self.colors["text"]),
                                   ("disabled", self.colors["text"])])

    def create_header_frame(self):
        header_frame = ttk.Frame(self.main_container, style="Header.TFrame")
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Server controls
        controls_frame = ttk.Frame(header_frame, style="Header.TFrame")
        controls_frame.pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_frame, text="Server IP:", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        self.host_entry = ttk.Entry(controls_frame, width=15)
        self.host_entry.insert(0, "0.0.0.0")
        self.host_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_frame, text="Port:", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        self.port_entry = ttk.Entry(controls_frame, width=6)
        self.port_entry.insert(0, str(self.chat_server.port))
        self.port_entry.pack(side=tk.LEFT, padx=5)

        self.start_button = ttk.Button(controls_frame, text="Start Server",
                                       command=self.start, style="Control.TButton")
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(controls_frame, text="Stop Server",
                                      command=self.stop, style="Danger.TButton", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Server status
        status_frame = ttk.Frame(header_frame, style="Header.TFrame")
        status_frame.pack(side=tk.RIGHT, padx=5)

        self.status_label = ttk.Label(status_frame, text="Server Status: Stopped",
                                      style="Header.TLabel")
        self.status_label.pack(side=tk.RIGHT, padx=5)

    def create_main_content(self):
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(expand=True, fill=tk.BOTH, pady=5)

        # Server Log Tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Server Log")

        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(log_controls, text="Export Logs",
                   command=self.export_logs, style="Action.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="Clear Logs",
                   command=self.clear_logs, style="Danger.TButton").pack(side=tk.LEFT, padx=5)

        self.text_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD,
                                                     height=15, font=("Consolas", 10))
        self.text_widget.pack(expand=True, fill=tk.BOTH, pady=5)

        # Clients Tab
        clients_frame = ttk.Frame(self.notebook)
        self.notebook.add(clients_frame, text="Connected Clients")

        # Client controls
        client_controls = ttk.Frame(clients_frame)
        client_controls.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(client_controls, text="Disconnect Selected",
                   command=self.disconnect_selected_client,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(client_controls, text="Disconnect All",
                   command=self.disconnect_all_clients,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(client_controls, text="Refresh List",
                   command=self.update_client_list,
                   style="Action.TButton").pack(side=tk.LEFT, padx=5)

        # Create treeview for clients
        columns = ("IP", "Port", "Connected Time", "Active Rooms")
        self.clients_tree = ttk.Treeview(clients_frame, columns=columns, show="headings")

        # Configure columns
        for col in columns:
            self.clients_tree.heading(col, text=col)
            self.clients_tree.column(col, width=150)

        self.clients_tree.pack(expand=True, fill=tk.BOTH, pady=5)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(clients_frame, orient=tk.VERTICAL,
                                  command=self.clients_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.clients_tree.configure(yscrollcommand=scrollbar.set)

        # Rooms Tab
        rooms_frame = ttk.Frame(self.notebook)
        self.notebook.add(rooms_frame, text="Chat Rooms")

        # Room controls
        room_controls = ttk.Frame(rooms_frame)
        room_controls.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(room_controls, text="Close Selected Room",
                   command=self.close_selected_room,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(room_controls, text="Close All Rooms",
                   command=self.close_all_rooms,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(room_controls, text="Refresh Rooms",
                   command=self.update_rooms_list,
                   style="Action.TButton").pack(side=tk.LEFT, padx=5)

        # Create treeview for rooms
        room_columns = ("Room Name", "Active Users", "Messages")
        self.rooms_tree = ttk.Treeview(rooms_frame, columns=room_columns, show="headings")

        for col in room_columns:
            self.rooms_tree.heading(col, text=col)
            self.rooms_tree.column(col, width=150)

        self.rooms_tree.pack(expand=True, fill=tk.BOTH, pady=5)

        # Add scrollbar
        room_scrollbar = ttk.Scrollbar(rooms_frame, orient=tk.VERTICAL,
                                       command=self.rooms_tree.yview)
        room_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rooms_tree.configure(yscrollcommand=room_scrollbar.set)

    def create_status_bar(self):
        status_bar = ttk.Frame(self.main_container, style="Status.TFrame")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.connection_count = ttk.Label(status_bar,
                                          text="Connections: 0", style="Status.TLabel")
        self.connection_count.pack(side=tk.LEFT, padx=5)

        self.message_count = ttk.Label(status_bar,
                                       text="Messages: 0", style="Status.TLabel")
        self.message_count.pack(side=tk.LEFT, padx=5)

        self.uptime_label = ttk.Label(status_bar,
                                      text="Uptime: 0:00:00", style="Status.TLabel")
        self.uptime_label.pack(side=tk.RIGHT, padx=5)

    def update_status_bar(self):
        stats = self.chat_server.get_stats()

        if stats["running"]:
            self.connection_count.config(
                text=f"Active Connections: {stats['active_connections']}")
            self.message_count.config(
                text=f"Total Messages: {stats['total_messages']}")

            if stats["uptime"]:
                hours = stats["uptime"].seconds // 3600
                minutes = (stats["uptime"].seconds % 3600) // 60
                seconds = stats["uptime"].seconds % 60
                self.uptime_label.config(
                    text=f"Uptime: {hours}:{minutes:02d}:{seconds:02d}")

        self.root.after(1000, self.update_status_bar)

    def start(self):
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())

            success, message = self.chat_server.start(host, port)

            if success:
                self.status_label.config(text="Server Status: Running")
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
                self.host_entry.config(state=tk.DISABLED)
                self.port_entry.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Error", message)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
            self.update_text_widget(f"Failed to start server: {str(e)}\n")

    def stop(self):
        if messagebox.askyesno("Confirm Stop", "Are you sure you want to stop the server?"):
            success, message = self.chat_server.stop()

            if success:
                self.status_label.config(text="Server Status: Stopped")
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.host_entry.config(state=tk.NORMAL)
                self.port_entry.config(state=tk.NORMAL)
            else:
                messagebox.showerror("Error", message)

    def update_text_widget(self, message):
        # This method is used as a callback for the server's log_callback
        self.text_widget.configure(state=tk.NORMAL)
        self.text_widget.insert(tk.END, message + "\n")
        self.text_widget.configure(state=tk.DISABLED)
        self.text_widget.see(tk.END)

    def update_client_list(self):
        # Clear existing items
        for item in self.clients_tree.get_children():
            self.clients_tree.delete(item)

        # Get client list from server
        client_list = self.chat_server.get_client_list()

        # Add clients to treeview
        for client in client_list:
            rooms = ", ".join(client["rooms"]) or "None"

            self.clients_tree.insert("", tk.END, values=(
                client["ip"],
                client["port"],
                client["connected_time"],
                rooms
            ))

    def update_rooms_list(self):
        # Clear existing items
        for item in self.rooms_tree.get_children():
            self.rooms_tree.delete(item)

        # Get room list from server
        room_list = self.chat_server.get_room_list()

        # Add rooms to treeview
        for room in room_list:
            self.rooms_tree.insert("", tk.END, values=(
                room["name"],
                room["active_users"],
                room["message_count"]
            ))

    def disconnect_selected_client(self):
        selection = self.clients_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a client to disconnect")
            return

        if messagebox.askyesno("Confirm Disconnect", "Are you sure you want to disconnect the selected client?"):
            for item in selection:
                values = self.clients_tree.item(item)['values']
                ip, port = values[0], values[1]

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
        selection = self.rooms_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a room to close")
            return

        if messagebox.askyesno("Confirm Close Room", "Are you sure you want to close the selected room?"):
            for item in selection:
                values = self.rooms_tree.item(item)['values']
                room_name = values[0]

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
            self.text_widget.configure(state=tk.NORMAL)
            self.text_widget.delete(1.0, tk.END)
            self.text_widget.configure(state=tk.DISABLED)

    def export_logs(self):
        """Export server logs to a file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"server_log_{timestamp}.txt"

            with open(filename, "w") as f:
                f.write(self.text_widget.get("1.0", tk.END))

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

        info = f"""
    Server Information:
    ------------------
    Host: {stats['host'] or 'Not running'}
    Port: {stats['port']}
    Status: {'Running' if stats['running'] else 'Stopped'}

    Statistics:
    -----------
    Total Connections: {stats['total_connections']}
    Active Connections: {stats['active_connections']}
    Total Messages: {stats['total_messages']}
    Active Rooms: {stats['active_rooms']}
    Uptime: {uptime_str}
    """
        messagebox.showinfo("Server Information", info)

    def on_closing(self):
        if self.chat_server.is_running:
            if messagebox.askyesno("Quit", "Server is running. Stop server and quit?"):
                self.chat_server.stop()
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        # Add menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_command(label="Clear Logs", command=self.clear_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        # Server menu
        server_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Server", menu=server_menu)
        server_menu.add_command(label="Start Server", command=self.start)
        server_menu.add_command(label="Stop Server", command=self.stop)
        server_menu.add_separator()
        server_menu.add_command(label="Server Information", command=self.show_server_info)

        # Clients menu
        clients_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Clients", menu=clients_menu)
        clients_menu.add_command(label="Disconnect Selected", command=self.disconnect_selected_client)
        clients_menu.add_command(label="Disconnect All", command=self.disconnect_all_clients)
        clients_menu.add_separator()
        clients_menu.add_command(label="Refresh Client List", command=self.update_client_list)

        # Rooms menu
        rooms_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Rooms", menu=rooms_menu)
        rooms_menu.add_command(label="Close Selected Room", command=self.close_selected_room)
        rooms_menu.add_command(label="Close All Rooms", command=self.close_all_rooms)
        rooms_menu.add_separator()
        rooms_menu.add_command(label="Refresh Room List", command=self.update_rooms_list)

        # Start the main event loop
        self.root.mainloop()


if __name__ == "__main__":
    server_gui = ServerGUI()
    server_gui.run()