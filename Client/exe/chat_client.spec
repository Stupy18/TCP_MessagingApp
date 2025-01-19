# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None

# Get absolute paths to assets
assets_path = os.path.abspath(os.path.join('..', '..', 'assets'))
icon_path = os.path.join(assets_path, 'icon.ico')
join_path = os.path.join(assets_path, 'join.ico')
room_path = os.path.join(assets_path, 'room.ico')

a = Analysis(
    ['launcher.py'],
    pathex=['E:/python/Licenta_MessagingApp/Client'],
    binaries=[],
    datas=[
        (icon_path, '.'),  # Changed to root directory
        (join_path, '.'),  # Changed to root directory
        (room_path, '.'),  # Changed to root directory
        ('../ChatClient.py', '.'),
        ('../ChatClientGUI.py', '.'),
        ('../LoginPopup.py', '.'),
        ('../RoomPopup.py', '.'),
        ('../../TLS/AES_GCM_CYPHER.py', 'TLS'),
        ('../../TLS/DigitalSigniture.py', 'TLS'),
        ('../../TLS/KeyDerivation.py', 'TLS'),
        ('../../TLS/KeyExchange.py', 'TLS'),
        ('../../TLS/OpenSSlCertHandler.py', 'TLS'),
        ('launcher.py', '.')
    ],
    hiddenimports=[
        'customtkinter',
        'cryptography',
        'cryptography.hazmat',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.kdf',
        'cryptography.hazmat.primitives.kdf.hkdf',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.asymmetric.ec',
        'cryptography.hazmat.primitives.asymmetric.x25519',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.primitives.padding',
        'cryptography.hazmat.primitives.serialization',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.backends.openssl',
        'cryptography.hazmat.backends.openssl.backend',
        'socket',
        'json',
        'base64',
        'time',
        'threading',
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SecureChat',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path  # Using absolute path
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SecureChat'
)