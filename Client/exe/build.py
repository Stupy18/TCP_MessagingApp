import os
import shutil
import subprocess


def build_executable():
    # Get current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Clean previous builds
    build_dir = os.path.join(current_dir, 'build')
    dist_dir = os.path.join(current_dir, 'dist')
    release_dir = os.path.join(current_dir, 'release')

    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    if os.path.exists(release_dir):
        shutil.rmtree(release_dir)

    # Run PyInstaller
    subprocess.run(['pyinstaller', 'chat_client.spec'])

    # Create release folder
    os.makedirs(release_dir)

    # Copy from dist to release
    secure_chat_dir = os.path.join(dist_dir, 'SecureChat')
    if os.path.exists(secure_chat_dir):
        release_chat_dir = os.path.join(release_dir, 'SecureChat')
        shutil.copytree(secure_chat_dir, release_chat_dir)
        print(f"\nBuild completed successfully!")
        print(f"Executable is in: {release_chat_dir}")
        print("You can distribute the entire 'SecureChat' folder from the release directory.")
    else:
        print(f"\nError: Build failed - {secure_chat_dir} not found")
        print("Check the build output above for errors.")


if __name__ == "__main__":
    build_executable()