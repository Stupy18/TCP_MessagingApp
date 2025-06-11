import threading
from tkinter import messagebox


class EventHandlers:
    """Handles UI events and provides thread-safe callback management"""

    def __init__(self, root, chat_client, header_section, chat_section, rooms_section, status_bar):
        self.root = root
        self.chat_client = chat_client
        self.header_section = header_section
        self.chat_section = chat_section
        self.rooms_section = rooms_section
        self.status_bar = status_bar

        # State management
        self.current_room = None
        self.room_messages = {}

    def safe_callback(self, func):
        """Create a thread-safe wrapper around a callback function"""

        def callback(*args, **kwargs):
            if self.root.winfo_exists():
                self.root.after(0, lambda: func(*args, **kwargs))

        return callback

    def handle_connect(self):
        """Handle the connect button click"""
        if not self.chat_client.connected:
            try:
                connection_details = self.header_section.get_connection_details()
                server_ip = connection_details['ip']
                server_port = int(connection_details['port'])
                username = connection_details['username']

                if not username:
                    messagebox.showerror("Error", "Username cannot be empty")
                    return

                success, message = self.chat_client.connect_to_server(server_ip, server_port, username)
                if success:
                    self.update_connection_ui(True)
                    self.chat_section.append_to_chat(f"Connected to {server_ip}:{server_port}\n")
                    self.status_bar.set_connected_status(username, f"{server_ip}:{server_port}")

                    # Start listening thread with better error handling
                    def listen_thread():
                        try:
                            self.chat_client.listen_for_messages()
                        except Exception as e:
                            print(f"Listener thread error: {str(e)}")
                            # Try to update UI safely
                            if self.root.winfo_exists():
                                self.root.after(0,
                                                lambda: self.status_bar.set_error_status(f"Connection error: {str(e)}"))

                    thread = threading.Thread(target=listen_thread, daemon=True)
                    thread.start()
                else:
                    self.status_bar.set_error_status(message)
                    messagebox.showerror("Connection Error", message)

            except Exception as e:
                self.status_bar.set_error_status(str(e))
                messagebox.showerror("Connection Error", str(e))

    def handle_send_message(self):
        """Handle sending a message"""
        message = self.chat_section.get_message_text()
        if message and self.current_room:
            success, response = self.chat_client.send_message(message, self.current_room)
            if success:
                self.chat_section.clear_message_input()
                # Add the message to the current room's history
                if self.current_room not in self.room_messages:
                    self.room_messages[self.current_room] = []
                self.room_messages[self.current_room].append(response)

                # Update the display
                self.chat_section.append_to_chat(response)
            else:
                self.status_bar.update_status(response, 'error')
        elif not self.current_room:
            self.status_bar.update_status("Please select a room first", 'error')

    def handle_join_room(self, room_name, password=None):
        """Handle joining a room"""
        if not room_name:
            self.status_bar.update_status("Please enter a valid room name", 'error')
            return

        # Check if we're already in this room
        if self.rooms_section.room_exists(room_name):
            self.status_bar.update_status(f"Already in room: {room_name}", 'info')
            return

        success, response = self.chat_client.join_room(room_name, password)
        if success:
            # Show attempting to join status
            self.status_bar.set_room_status(room_name, 'joining')
        else:
            self.status_bar.update_status(f"Failed to send join request: {response}", 'error')

    def handle_leave_room(self, room_name):
        """Handle leaving a room"""
        success, response = self.chat_client.leave_room(room_name)
        if success:
            # Remove the room button
            self.rooms_section.remove_room_button(room_name)

            # Clear room messages
            if room_name in self.room_messages:
                del self.room_messages[room_name]

            # If this was the current room, clear the chat
            if self.current_room == room_name:
                self.current_room = None
                self.chat_section.update_chat_header("💬 MESSAGES")
                self.chat_section.clear_chat()
                self.chat_section.append_to_chat("You left the room. Please select another room.\n")

                # Auto-select another room if available
                room_buttons = self.rooms_section.get_room_buttons()
                if room_buttons:
                    first_room_name = room_buttons[0][0]
                    self.handle_select_room(first_room_name)

            self.status_bar.set_room_status(room_name, 'left')
        else:
            self.status_bar.update_status(f"Failed to leave room: {response}", 'error')

    def handle_select_room(self, room_name):
        """Handle selecting a room"""
        # Update the current room
        self.current_room = room_name

        # Update the chat header to show the current room
        self.chat_section.update_chat_header(f"💬 ROOM: {room_name}")

        # Clear the chat log and show only messages for this room
        self.refresh_chat_display()

        # Highlight the selected room button
        self.rooms_section.highlight_selected_room(room_name)

    def handle_incoming_message(self, message):
        """Handle incoming messages from the server"""
        # Handle successful room join (receiving encryption key)
        if message.startswith("Received encryption key for room:"):
            room_name = message.split(":")[-1].strip()

            # Create room button if it doesn't exist
            if not self.rooms_section.room_exists(room_name):
                self.rooms_section.add_room_button(room_name)

                # Add welcome message to room
                join_message = f"→ You joined room: {room_name}"
                if room_name not in self.room_messages:
                    self.room_messages[room_name] = []
                self.room_messages[room_name].append(join_message)

                # Auto-select room if it's our first one
                if not self.current_room:
                    self.handle_select_room(room_name)
                elif self.current_room == room_name:
                    # Refresh display
                    self.refresh_chat_display()

                self.status_bar.set_room_status(room_name, 'joined')
            return

        # Handle errors (like wrong password)
        if message.startswith("Error:"):
            self.status_bar.update_status(message, 'error')
            return

        # Regular room messages
        if message.startswith("[") and "]" in message:
            room_end = message.find("]")
            room_name = message[1:room_end].strip()

            # Extract content after room prefix
            message_content = message[room_end + 1:].strip()

            # Store in room history
            if room_name in self.chat_client.rooms:
                if room_name not in self.room_messages:
                    self.room_messages[room_name] = []
                self.room_messages[room_name].append(message_content)

                # Update display if current room
                if room_name == self.current_room:
                    self.chat_section.append_to_chat(message_content)
            return

        # System messages or general messages
        if message.startswith("[SYSTEM]"):
            # Add to all rooms
            for room in self.chat_client.rooms:
                if room not in self.room_messages:
                    self.room_messages[room] = []
                self.room_messages[room].append(message)

            # Display in current room
            if self.current_room:
                self.chat_section.append_to_chat(message)
            return

        # Other messages
        self.chat_section.append_to_chat(message)

    def handle_room_closed(self, room_name):
        """Handle when a room is closed by the server"""
        # Remove the room button from the GUI
        self.rooms_section.remove_room_button(room_name)

        # Clean up room messages
        if room_name in self.room_messages:
            del self.room_messages[room_name]

        # If this was the current room, clear the display and reset
        if self.current_room == room_name:
            self.current_room = None
            self.chat_section.update_chat_header("💬 MESSAGES")
            self.chat_section.clear_chat()
            self.chat_section.append_to_chat("The current room has been closed.\nPlease select another room.\n")

            # Auto-select another room if available
            room_buttons = self.rooms_section.get_room_buttons()
            if room_buttons:
                first_room_name = room_buttons[0][0]
                self.handle_select_room(first_room_name)

    def refresh_chat_display(self):
        """Refresh the chat display for the current room"""
        if self.current_room and self.current_room in self.room_messages:
            self.chat_section.set_chat_content(self.room_messages[self.current_room])
        else:
            self.chat_section.clear_chat()

    def update_connection_ui(self, connected):
        """Update UI elements based on connection state"""
        self.header_section.update_connection_ui(connected)
        self.chat_section.update_connection_ui(connected)

    def get_current_room(self):
        """Get the currently selected room"""
        return self.current_room

    def get_room_messages(self, room_name):
        """Get messages for a specific room"""
        return self.room_messages.get(room_name, [])

    def setup_callbacks(self):
        """Setup all the callbacks for the chat client"""
        # Set the chat client callbacks to use thread-safe wrappers
        self.chat_client.message_callback = self.safe_callback(self.handle_incoming_message)
        self.chat_client.room_closed_callback = self.safe_callback(self.handle_room_closed)