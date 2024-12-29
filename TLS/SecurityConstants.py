

class SecurityConstants:
    """Global security constants for the application"""

    # Fixed block size for all operations (128 bytes)
    BLOCK_SIZE = 128

    # Initial hash value (32 bytes of zeros)
    INITIAL_HASH = b'\0' * 32

    # Hash output size (SHA-256 = 32 bytes)
    HASH_SIZE = 32