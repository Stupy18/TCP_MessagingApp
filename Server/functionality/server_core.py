import socket
import threading
from datetime import datetime


class ServerCore:
    """Handles basic server socket operations and connection management"""

    def __init__(self, log_callback=None):
        self.host = None
        self.port = 8080
        self.server_socket = None
        self.is_running = False
        self.accept_thread = None
        self.log_callback = log_callback
        self.client_handler = None  # Will be set by main server

    def start(self, host, port):
        """Start the server socket and begin accepting connections"""
        try:
            self.host = host
            self.port = int(port)

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(50)

            self.is_running = True
            self.log_message(f"Server started at {self.host}:{self.port}")

            # Create a separate thread for accepting connections
            self.accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            self.accept_thread.start()

            return True, "Server started successfully"

        except Exception as e:
            error_msg = f"Failed to start server: {str(e)}"
            self.log_message(error_msg)
            return False, error_msg

    def stop(self):
        """Stop the server and close all connections"""
        self.is_running = False

        # Close the server socket to stop accept_connections
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None

        # Wait for accept thread to finish if it exists
        if self.accept_thread and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=1.0)

        self.log_message("Server stopped.")
        return True, "Server stopped successfully"

    def accept_connections(self):
        """Handle incoming client connections"""
        while self.is_running:
            try:
                client_socket, client_address = self.server_socket.accept()

                # Delegate client handling to the main server
                if self.client_handler:
                    client_thread = threading.Thread(
                        target=self.client_handler,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()

            except Exception as e:
                if self.is_running:  # Only show error if server is still meant to be running
                    self.log_message(f"Error accepting connection: {str(e)}")

    def set_client_handler(self, handler_func):
        """Set the client handling function"""
        self.client_handler = handler_func

    def log_message(self, message):
        """Log messages and call the callback if provided"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        print(formatted_message)
        if self.log_callback:
            self.log_callback(formatted_message)

    def is_server_running(self):
        """Check if the server is currently running"""
        return self.is_running

    def get_server_info(self):
        """Get basic server information"""
        return {
            "host": self.host,
            "port": self.port,
            "running": self.is_running
        }