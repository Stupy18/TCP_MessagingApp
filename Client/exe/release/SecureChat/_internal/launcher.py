import os
import sys
import traceback
from tkinter import messagebox


def setup_paths():
    # Get the directory containing the executable
    if getattr(sys, 'frozen', False):
        # Running as compiled
        base_path = os.path.dirname(sys.executable)
    else:
        # Running from script
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Add the base path to system path
    if base_path not in sys.path:
        sys.path.insert(0, base_path)


def main():
    try:
        from ChatClientGUI import ChatGUI
        gui = ChatGUI()
        gui.run()
    except Exception as e:
        error_msg = f"Application failed to start:\n\n{str(e)}\n\nTraceback:\n{traceback.format_exc()}"
        messagebox.showerror("Fatal Error", error_msg)
        sys.exit(1)


if __name__ == "__main__":
    main()