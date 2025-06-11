import os
import sys

def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
            return os.path.join(base_path, relative_path)
        else:
            # We're running in development mode
            return os.path.join('../../assets', relative_path)
    except Exception:
        return os.path.join('../../assets', relative_path)