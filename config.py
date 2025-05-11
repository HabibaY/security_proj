import os

# Base directories
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
USER_DATA_DIR = os.path.join(PROJECT_ROOT, "user_data")
SHARED_DIR = os.path.join(PROJECT_ROOT, "shared_files")
RECEIVED_DIR = os.path.join(PROJECT_ROOT, "received_files")

# Create necessary directories
os.makedirs(USER_DATA_DIR, exist_ok=True)
os.makedirs(SHARED_DIR, exist_ok=True)
os.makedirs(RECEIVED_DIR, exist_ok=True)

# File paths
USER_DATA_FILE = os.path.join(USER_DATA_DIR, "users.json")
KEY_FILE = os.path.join(USER_DATA_DIR, "key.bin")

# Session settings
# Timeout settings (seconds)
KEY_EXCHANGE_TIMEOUT = 10
FILE_TRANSFER_TIMEOUT = 30
CONNECTION_TIMEOUT = 5
SESSION_TIMEOUT = 30    # minutes
RENDEZVOUS_PORT = 5000  # port for the rendezvous tracker
DISCOVERY_PORT = 50000  # UDP port for LAN broadcast discovery
TCP_DEFAULT_PORT = 5001    # fallback port for peer server

