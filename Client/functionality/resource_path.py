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
            # Get the directory where the current script is located
            current_file = os.path.abspath(__file__)

            # Navigate up to find the project root (where assets folder is)
            # From Client/functionality/resource_path.py -> go up 2 levels to project root
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))

            # Construct path to assets
            assets_path = os.path.join(project_root, 'assets', relative_path)

            if os.path.exists(assets_path):
                return assets_path
            else:
                # Fallback: try relative to current working directory
                cwd_path = os.path.join(os.getcwd(), 'assets', relative_path)
                if os.path.exists(cwd_path):
                    return cwd_path

                # Final fallback
                print(f"Warning: Could not find asset at {assets_path} or {cwd_path}")
                return assets_path

    except Exception as e:
        print(f"Error in get_resource_path: {e}")
        return os.path.join('assets', relative_path)