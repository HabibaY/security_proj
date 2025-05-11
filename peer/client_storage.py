# peer/client_storage.py
import os
import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from peer.crypto_utils import derive_key_from_password
from config import USER_DATA_FILE

class ClientAuthStore:
    def __init__(self, storage_path="USER_DATA_FILE.enc"):
        self.storage_path = storage_path
        self.salt_path = storage_path + ".salt"
        
    def store_credentials(self, password, credentials):
        """Store credentials encrypted with client-specific password using AES-GCM"""
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)  # 96-bit nonce is recommended for GCM
        key = derive_key_from_password(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        plaintext = json.dumps(credentials).encode()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Store: [salt][nonce][tag][ciphertext]
        with open(self.storage_path, 'wb') as f:
            f.write(salt + nonce + encryptor.tag + ciphertext)
    
    def load_credentials(self, password):
        """Load and decrypt credentials using client password and AES-GCM"""
        try:
            with open(self.storage_path, 'rb') as f:
                data = f.read()
                salt = data[:16]
                nonce = data[16:28]
                tag = data[28:44]
                ciphertext = data[44:]
                
                key = derive_key_from_password(password, salt)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                return json.loads(plaintext.decode())
        except Exception:
            return None
