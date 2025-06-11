import customtkinter as ctk
from tkinter import messagebox, scrolledtext
from datetime import datetime


class LogsTab:
    """Manages the logs tab with log display and controls"""

    def __init__(self, parent, colors):
        self.parent = parent
        self.colors = colors
        self.text_widget = None

    def setup_logs_tab(self):
        """Setup the complete logs tab"""
        log_frame = self.parent

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

    def update_text_widget(self, message):
        """Add a message to the log display"""
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", message + "\n")
        self.text_widget.configure(state="disabled")
        self.text_widget.see("end")

    def clear_logs(self):
        """Clear all logs with confirmation"""
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

    def get_text_widget(self):
        """Get the text widget for external updates"""
        return self.text_widget