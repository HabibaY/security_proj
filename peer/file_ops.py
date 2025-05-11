# peer/file_ops.py

import os
from config import SHARED_DIR, RECEIVED_DIR

def list_shared_files():
    """Return a list of filenames in the shared directory."""
    try:
        return os.listdir(SHARED_DIR)
    except FileNotFoundError:
        os.makedirs(SHARED_DIR, exist_ok=True)
        return []

def send_encrypted_file(conn, filename, session_key):
    """Send an encrypted file over a socket connection using session key"""
    path = os.path.join(SHARED_DIR, filename)
    try:
        with open(path, "rb") as f:
            plaintext = f.read()
        
        # Encrypt the file contents with session key
        from peer.crypto_utils import encrypt
        ciphertext = encrypt(plaintext, session_key)
        
        # Send length as header
        length_header = f"{len(ciphertext)}\n".encode()
        conn.sendall(length_header)
        
        # Send encrypted data in chunks
        chunk_size = 8192
        sent = 0
        while sent < len(ciphertext):
            chunk = ciphertext[sent:sent + chunk_size]
            conn.sendall(chunk)
            sent += len(chunk)
            
        return True
    except Exception as e:
        print(f"[-] Error sending file: {e}")
        return False

def receive_encrypted_file(conn, filename, session_key):
    """Receive and decrypt a file using session key"""
    try:
        # 1) read the length header
        header = b""
        while not header.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                raise ConnectionError("Connection closed during header read")
            header += chunk
        total = int(header.decode().strip())

        # 2) read exactly that many bytes
        data = b""
        while len(data) < total:
            chunk = conn.recv(min(4096, total - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed during file transfer")
            data += chunk

        # 3) decrypt and write
        from peer.crypto_utils import decrypt
        plaintext = decrypt(data, session_key)
        
        os.makedirs(RECEIVED_DIR, exist_ok=True)
        out = os.path.join(RECEIVED_DIR, filename)
        with open(out, "wb") as f:
            f.write(plaintext)
        
        return True
    except Exception as e:
        print(f"[-] Error receiving file: {e}")
        return False