# peer/crypto_utils.py
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_parameters


# Path to DH params file (shared between peers)
DH_PARAMS_FILE = "dh_params.pem"

# Encrypt data
def encrypt(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM requires 12 bytes
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct  # prepend nonce


# Decrypt data
# Decrypt data
def decrypt(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ct = data[12:]
    return aesgcm.decrypt(nonce, ct, None)


# Derive key from password using Argon2id
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.ID
    )

# Automatically load or create DH parameters
def load_or_create_dh_parameters(path=DH_PARAMS_FILE):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return load_pem_parameters(f.read())


    else:
        print("[*] dh_params.pem not found — generating new DH parameters...")
        params = dh.generate_parameters(generator=2, key_size=2048)
        with open(path, "wb") as f:
            f.write(params.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            ))
        print("[+] dh_params.pem generated and saved.")
        return params

# Load shared parameters once for both peers
DH_PARAMETERS = load_or_create_dh_parameters()

def generate_dh_key_pair():
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(data):
    return serialization.load_pem_public_key(data)

def derive_shared_secret(private_key, peer_public_key):
    try:
        shared_key = private_key.exchange(peer_public_key)
        return hashlib.sha256(shared_key).digest()
    except Exception as e:
        print(f"Error deriving shared secret: {e}")
        raise ValueError("Error computing shared key.")
