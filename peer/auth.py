# peer/auth.py

import os
import json
import secrets  
from datetime import datetime, timedelta

from config import USER_DATA_FILE, SESSION_TIMEOUT
from argon2 import PasswordHasher, exceptions
from peer.crypto_utils import encrypt, decrypt, derive_key_from_password

# Argon2id hasher configuration
_ph = PasswordHasher(
    time_cost=2,        # number of iterations
    memory_cost=102400, # memory usage in KiB (100 MiB)
    parallelism=8,      # number of parallel lanes
    hash_len=32,        # length of the hash
    salt_len=16         # length of the random salt
)

# In-memory session store: { token: { username, expiry } }
active_sessions = {}

# On-disk files for encrypted credentials store
SALT_FILE = USER_DATA_FILE + ".salt"
ENC_FILE  = USER_DATA_FILE + ".enc"

def _ensure_data_dir():
    os.makedirs(os.path.dirname(USER_DATA_FILE), exist_ok=True)

def _init_store(password: str):
    """
    Bootstrap an empty encrypted user store protected by `password`.
    """
    _ensure_data_dir()
    # 1) Generate and save a random salt
    salt = secrets.token_bytes(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)

    # 2) Derive key & encrypt an empty dict
    key = derive_key_from_password(password, salt)
    blob = encrypt(json.dumps({}).encode("utf-8"), key)
    with open(ENC_FILE, "wb") as f:
        f.write(blob)

def _load_store(password: str) -> dict:
    """
    Decrypt and return the JSON user-store using `password`.
    Raises FileNotFoundError if store not initialized, or decrypt errors on bad password.
    """
    if not (os.path.exists(SALT_FILE) and os.path.exists(ENC_FILE)):
        raise FileNotFoundError("Encrypted user store not initialized")
    salt = open(SALT_FILE, "rb").read()
    key  = derive_key_from_password(password, salt)
    blob = open(ENC_FILE, "rb").read()
    plaintext = decrypt(blob, key)
    return json.loads(plaintext.decode("utf-8"))

def _save_store(users: dict, password: str):
    """
    Encrypt and overwrite the JSON user-store under the existing salt.
    """
    salt = open(SALT_FILE, "rb").read()
    key  = derive_key_from_password(password, salt)
    blob = encrypt(json.dumps(users, indent=2).encode("utf-8"), key)
    with open(ENC_FILE, "wb") as f:
        f.write(blob)

def hash_password(password: str) -> str:
    """
    Hash `password` using Argon2id.
    Returns the encoded hash string (includes salt & parameters).
    """
    return _ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verify a plaintext `password` against the Argon2id `stored_hash`.
    """
    try:
        return _ph.verify(stored_hash, password)
    except exceptions.VerifyMismatchError:
        return False

def register_user(username: str, password: str) -> tuple[bool, str]:
    """
    Register a new user:
     - On first ever run, bootstraps the encrypted store under `password`.
     - Decrypts the store, adds the new user with an Argon2 hash, re-encrypts.
    Returns (success, message).
    """
    try:
        # Initialize on first run
        if not os.path.exists(ENC_FILE):
            _init_store(password)
        users = _load_store(password)
    except FileNotFoundError:
        return False, "Failed to initialize user store"
    except Exception:
        return False, "Wrong password: cannot decrypt user store"

    if username in users:
        return False, "Username already exists"

    # Add new user
    users[username] = {"password_hash": hash_password(password)}

    try:
        _save_store(users, password)
        return True, "Registration successful"
    except Exception as e:
        return False, f"Failed to save user store: {e}"

def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate by decrypting the store with `password` and verifying `username`.
    Returns True if credentials are valid.
    """
    try:
        users = _load_store(password)
    except Exception:
        return False

    record = users.get(username)
    if not record:
        return False

    return verify_password(record["password_hash"], password)

# Update create_session_token in auth.py
def create_session_token(username: str):
    """Create session token without pre-generating key"""
    token = secrets.token_hex(16)
    expiry = datetime.now() + timedelta(minutes=SESSION_TIMEOUT)
    active_sessions[token] = {
        "username": username,
        "expiry": expiry,
        # No key generated yet - will be negotiated during file transfer
    }
    return token

def is_session_valid(token: str) -> bool:
    """
    Check token validity & expiry.
    """
    sess = active_sessions.get(token)
    if not sess or datetime.now() > sess["expiry"]:
        active_sessions.pop(token, None)
        return False
    return True

def renew_session(token: str):
    """
    Extend an existing session token by SESSION_TIMEOUT minutes.
    """
    if token in active_sessions:
        active_sessions[token]["expiry"] = datetime.now() + timedelta(minutes=SESSION_TIMEOUT)

# Modify register_user and authenticate_user to use in-memory storage:
users = {}  # In-memory user store

def register_user(username: str, password: str) -> tuple[bool, str]:
    if username in users:
        return False, "Username already exists"
    
    users[username] = {
        "password_hash": hash_password(password)
    }
    return True, "Registration successful"

def authenticate_user(username: str, password: str) -> bool:
    record = users.get(username)
    if not record:
        return False
    return verify_password(record["password_hash"], password)
