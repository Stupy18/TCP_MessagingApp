import pygame
import os
from threading import Thread
from Client.functionality.resource_path import get_resource_path


class SoundManager:
    """Manages sound effects for the chat application"""

    def __init__(self):
        self.enabled = True
        self.volume = 0.5
        self.sounds = {}
        self.initialize_pygame()
        self.load_sounds()

    def initialize_pygame(self):
        """Initialize pygame mixer for sound playback"""
        try:
            pygame.mixer.init(frequency=22050, size=-16, channels=2, buffer=512)
            pygame.mixer.set_num_channels(8)  # Allow multiple sounds
        except Exception as e:
            print(f"Warning: Could not initialize sound system: {e}")
            self.enabled = False


    def load_sounds(self):
        """Load all sound files"""
        if not self.enabled:
            return

        # Updated sound mapping to match your actual files
        sound_files = {
            'message': 'message_sound.mp3',
            'connect': 'welcome.mp3',  # Using welcome for connect
            'disconnect': 'leaving_room.mp3',  # Using leaving_room for disconnect
            'join_room': 'joining_room.mp3',
            'leave_room': 'leaving_room.mp3',
            'error': 'error.mp3',
            'notification': 'message_sound.mp3'  # Reuse message sound for notifications
        }

        for sound_name, filename in sound_files.items():
            try:
                # Try to load from assets
                sound_path = get_resource_path(f"sounds/{filename}")
                if os.path.exists(sound_path):
                    self.sounds[sound_name] = pygame.mixer.Sound(sound_path)
                    self.sounds[sound_name].set_volume(self.volume)
                else:
                    print(f"Sound file not found: {sound_path}")
            except Exception as e:
                print(f"Warning: Could not load sound {filename}: {e}")

    def play_sound(self, sound_name, volume_override=None):
        """Play a sound effect"""
        if not self.enabled or sound_name not in self.sounds:
            return

        try:
            # Play sound in a separate thread to avoid blocking UI
            def play():
                sound = self.sounds[sound_name]
                if volume_override:
                    original_volume = sound.get_volume()
                    sound.set_volume(volume_override)
                    sound.play()
                    # Reset volume after a short delay
                    pygame.time.wait(100)
                    sound.set_volume(original_volume)
                else:
                    sound.play()

            Thread(target=play, daemon=True).start()
        except Exception as e:
            print(f"Error playing sound {sound_name}: {e}")

    def set_volume(self, volume):
        """Set the master volume (0.0 to 1.0)"""
        self.volume = max(0.0, min(1.0, volume))
        for sound in self.sounds.values():
            sound.set_volume(self.volume)

    def toggle_sounds(self):
        """Toggle sound on/off"""
        self.enabled = not self.enabled
        return self.enabled

    def cleanup(self):
        """Clean up pygame resources"""
        try:
            pygame.mixer.quit()
        except:
            pass