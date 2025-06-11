import customtkinter as ctk


class ChatSection:
    """Manages the chat display and message input area"""

    def __init__(self, parent, colors, send_message_callback):
        self.parent = parent
        self.colors = colors
        self.send_message_callback = send_message_callback
        self.chat_frame = None
        self.chat_header = None
        self.chat_header_label = None
        self.chat_log = None
        self.message_entry = None
        self.send_button = None

    def create_chat_section(self):
        """Create the complete chat section"""
        # Chat section
        self.chat_frame = ctk.CTkFrame(
            self.parent,
            fg_color=self.colors['surface'],
            corner_radius=15,
            border_width=1,
            border_color=self.colors['primary']
        )
        self.chat_frame.pack(side='left', expand=True, fill='both', padx=(0, 10))

        # Chat header
        self.chat_header = ctk.CTkFrame(self.chat_frame, fg_color="transparent", height=50)
        self.chat_header.pack(fill='x', padx=20, pady=15)
        self.chat_header.pack_propagate(False)

        self.chat_header_label = ctk.CTkLabel(
            self.chat_header,
            text="💬 MESSAGES",
            font=("Segoe UI", 16, "bold"),
            text_color=self.colors['primary']
        )
        self.chat_header_label.pack(side='left')

        # Chat log
        self.chat_log = ctk.CTkTextbox(
            self.chat_frame,
            font=("Segoe UI", 12),
            corner_radius=10,
            border_spacing=15,
            fg_color=self.colors['surface_dark'],
            border_color=self.colors['primary'],
            border_width=1
        )
        self.chat_log.pack(expand=True, fill='both', padx=20, pady=(0, 15))
        self.chat_log.configure(state='disabled')

        # Message input area
        input_frame = ctk.CTkFrame(self.chat_frame, fg_color="transparent", height=60)
        input_frame.pack(fill='x', padx=20, pady=(0, 20))
        input_frame.pack_propagate(False)

        self.message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="✍️ Type your message...",
            font=("Segoe UI", 12),
            height=45,
            state='disabled',
            fg_color=self.colors['surface_dark'],
            border_color=self.colors['primary'],
            border_width=1
        )
        self.message_entry.pack(side='left', expand=True, fill='x', padx=(0, 10))

        self.send_button = ctk.CTkButton(
            input_frame,
            text="Send",
            font=("Segoe UI", 13, "bold"),
            width=100,
            height=45,
            command=self.send_message_callback,
            state='disabled',
            fg_color=self.colors['secondary'],
            hover_color=self.colors['accent']
        )
        self.send_button.pack(side='right')

        return self.chat_frame

    def append_to_chat(self, message):
        """Add a message to the chat log"""
        self.chat_log.configure(state='normal')
        self.chat_log.insert('end', message + "\n")
        self.chat_log.see('end')
        self.chat_log.configure(state='disabled')

    def clear_chat(self):
        """Clear the chat log"""
        self.chat_log.configure(state='normal')
        self.chat_log.delete(1.0, 'end')
        self.chat_log.configure(state='disabled')

    def set_chat_content(self, messages):
        """Set the chat content to a list of messages"""
        self.chat_log.configure(state='normal')
        self.chat_log.delete(1.0, 'end')  # Clear all text

        for message in messages:
            self.chat_log.insert('end', message + "\n")

        self.chat_log.configure(state='disabled')
        self.chat_log.see('end')

    def get_message_text(self):
        """Get the current message text from the input field"""
        return self.message_entry.get().strip()

    def clear_message_input(self):
        """Clear the message input field"""
        self.message_entry.delete(0, 'end')

    def update_chat_header(self, text):
        """Update the chat header text"""
        if self.chat_header_label:
            self.chat_header_label.configure(text=text)

    def update_connection_ui(self, connected):
        """Update UI elements based on connection state"""
        opposite_state = 'normal' if connected else 'disabled'
        self.message_entry.configure(state=opposite_state)
        self.send_button.configure(state=opposite_state)

    def setup_bindings(self, root):
        """Setup keyboard bindings for the chat section"""
        self.message_entry.bind('<Return>', lambda e: self.send_message_callback())