import socket
from TLS.AES_GCM_CYPHER import send_encrypted_data, receive_encrypted_data, AESGCMCipher


class ConnectionManager:
    """Handles basic socket operations and network communication"""

    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.symmetric_key = None

    def connect_to_server(self, server_ip, server_port):
        """Establish socket connection to server"""
        try:
            self.client_socket.connect((server_ip, server_port))
            return True, f"Connected to {server_ip}:{server_port}"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        """Close the connection and reset socket"""
        self.connected = False
        try:
            self.client_socket.close()
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            pass

    def send_encrypted_message(self, message):
        """Send an encrypted message through the socket"""
        if self.symmetric_key is None:
            raise ValueError("No symmetric key available - please ensure you're connected")

        encrypted_data = AESGCMCipher.encrypt(self.symmetric_key, message)
        send_encrypted_data(self.client_socket, encrypted_data)

    def receive_encrypted_message(self):
        """Receive and decrypt a message from the socket"""
        if self.symmetric_key is None:
            raise ValueError("No symmetric key available")

        encrypted_data = receive_encrypted_data(self.client_socket)
        return AESGCMCipher.decrypt(self.symmetric_key, encrypted_data)

    def set_symmetric_key(self, key):
        """Set the symmetric key for encryption/decryption"""
        self.symmetric_key = key

    def get_server_address(self):
        """Get the server address from the socket"""
        return self.client_socket.getpeername()

    def is_connected(self):
        """Check if the connection is active"""
        return self.connected

    def set_connected(self, status):
        """Set the connection status"""
        self.connected = status