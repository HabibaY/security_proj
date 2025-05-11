# # peer/server.py

# import os
# import socket
# import threading
# import time

# from config import SHARED_DIR
# from peer.auth import (
#     register_user,
#     authenticate_user,
#     create_session_token,
#     is_session_valid,
#     renew_session
# )
# from peer.crypto_utils import (
#     encrypt, 
#     decrypt, 
#     generate_dh_key_pair, 
#     serialize_public_key, 
#     deserialize_public_key, 
#     derive_shared_secret
# )
# from peer.file_ops import list_shared_files

# def handle_key_exchange(conn, addr):
#     """Server-side key exchange with validation and debugging"""
#     import traceback
#     try:
#         conn.settimeout(30)
#         print(f"[DEBUG] Starting key exchange with {addr}")

#         # 1. Generate DH keys
#         print("[DEBUG] Generating DH keys...")
#         dh_private, dh_public = generate_dh_key_pair()
#         if not dh_private or not dh_public:
#             raise ValueError("Invalid DH keys generated")

#         # 2. Serialize and send server's public key
#         print("[DEBUG] Serializing public key...")
#         pubkey_bytes = serialize_public_key(dh_public)
#         if not pubkey_bytes or len(pubkey_bytes) < 100:
#             raise ValueError("Invalid public key serialization")

#         print("[DEBUG] Sending server's public key...")
#         conn.sendall(f"DH_PUBKEY:{len(pubkey_bytes)}\n".encode())
#         conn.sendall(pubkey_bytes)

#         # 3. Receive client's public key
#         print("[DEBUG] Waiting for client's key header...")
#         header = recv_until(conn, b"\n")
#         print(f"[DEBUG] Received client header: {header}")
        
#         if not header.startswith(b"CLIENT_PUBKEY:"):
#             raise ValueError("Invalid client header format")

#         try:
#             key_size = int(header[len(b"CLIENT_PUBKEY:"):].strip())
#             if key_size <= 0 or key_size > 10000:
#                 raise ValueError("Invalid client key size")
#         except ValueError:
#             raise ValueError("Malformed client key size")

#         print(f"[DEBUG] Receiving client key (size: {key_size})...")
#         client_key_bytes = recv_exact(conn, key_size)
#         # Sanity check: make sure we received the correct number of bytes
#         if len(client_key_bytes) != key_size:
#             raise ValueError(f"Expected {key_size} bytes but got {len(client_key_bytes)}")
#         print(f"[DEBUG] Client key preview:\n{client_key_bytes.decode(errors='ignore')[:200]}")


#         print(f"[DEBUG] Received client key (first 60 bytes): {client_key_bytes[:60]}...")
#         print(f"[DEBUG] Client key bytes length: {len(client_key_bytes)}")
#         print(f"[DEBUG] Client key starts with:\n{client_key_bytes[:60].decode(errors='ignore')}")
#         print(f"[DEBUG] Client key ends with:\n{client_key_bytes[-60:].decode(errors='ignore')}")


#         # 4. Deserialize and verify client's public key
#         print("[DEBUG] Deserializing client key...")
#         print(f"[DEBUG] Client key bytes length: {len(client_key_bytes)}")
#         print(f"[DEBUG] Client key preview:\n{client_key_bytes.decode(errors='ignore')[:200]}")

#         try:
#             client_pubkey = deserialize_public_key(client_key_bytes)
#         except Exception as e:
#             print("[DEBUG] Deserialization failed:", e)
#             raise ValueError("Client public key deserialization failed")


#         # 5. Derive shared secret
#         print("[DEBUG] Deriving shared secret...")
#         print("[DEBUG] Deserialization successful, computing shared secret...")

#         shared_secret = derive_shared_secret(dh_private, client_pubkey)
#         if not shared_secret or len(shared_secret) < 32:
#             raise ValueError("Invalid shared secret derived")

#         # 6. Send confirmation
#         print("[DEBUG] Successfully derived shared secret, sending confirmation...")
#         conn.sendall(b"KEY_EXCHANGE_COMPLETE\n")
#         print("[DEBUG] Key exchange completed successfully")
#         return shared_secret[:32]

#     except Exception as e:
#         print(f"[DEBUG] Key exchange failed: {e}")
#         try:
#             conn.sendall(b"KEY_EXCHANGE_FAILED\n")
#         except Exception as send_err:
#             print(f"[DEBUG] Failed to send KEY_EXCHANGE_FAILED: {send_err}")
#         print("[DEBUG] Full exception traceback:")
#         traceback.print_exc()
#         raise


# def recv_until(conn, delimiter):
#     """Server-side receive until delimiter"""
#     data = b""
#     while delimiter not in data:
#         chunk = conn.recv(1024)
#         if not chunk:
#             raise ConnectionError("Client disconnected")
#         data += chunk
#     return data

# def recv_exact(conn, length):
#     """Server-side receive exact bytes"""
#     data = b""
#     while len(data) < length:
#         chunk = conn.recv(min(4096, length - len(data)))
#         if not chunk:
#             raise ConnectionError(f"Expected {length} bytes, got {len(data)}")
#         data += chunk
#     return data

# def handle_incoming_peer(conn, addr):
#     try:
#         conn.settimeout(30)
        
#         data = conn.recv(1024)
#         if not data:
#             return
#         if data == b"PING":
#             conn.sendall(b"PONG")
#             return

#         text = data.decode().strip()
#         parts = text.split(maxsplit=1)
#         authenticated = False
#         token = ""
#         if len(parts) >= 1:
#             if len(parts[0]) == 32 and is_session_valid(parts[0]):
#                 token = parts[0]
#                 command = " ".join(parts[1:]) if len(parts) > 1 else ""
#                 authenticated = True
#                 renew_session(token)
#             else:
#                 command = text

#         # Authentication commands
#         if command.startswith("REGISTER"):
#             _, username, password = command.split(maxsplit=2)
#             ok, msg = register_user(username, password)
#             status = "OK" if ok else "ERROR"
#             conn.sendall(f"{status}: {msg}".encode())
#             return

#         elif command.startswith("LOGIN"):
#             _, username, password = command.split(maxsplit=2)
#             if authenticate_user(username, password):
#                 token = create_session_token(username)
#                 conn.sendall(f"OK: {token}".encode())
#             else:
#                 conn.sendall(b"ERROR: Invalid username or password")
#             return

#         # File operations
#         if command == "LIST_FILES":
#             if not authenticated:
#                 conn.sendall(b"ERROR: Authentication required")
#                 return
            
#             try:
#                 session_key = handle_key_exchange(conn, addr)
#                 print("[+] Key exchange successful")
                
#                 files = list_shared_files()
#                 if not files:
#                     conn.sendall(b"ERROR: No files available")
#                     return
                    
#                 file_list = "\n".join(files).encode()
#                 ciphertext = encrypt(file_list, session_key)
#                 conn.sendall(ciphertext)
#                 print(f"[+] Sent file list to {addr}")
#                 return
                    
#             except Exception as e:
#                 print(f"[!] LIST_FILES error: {e}")
#                 try:
#                     conn.sendall(f"ERROR: {str(e)}".encode())
#                 except:
#                     pass
#                 return

#         elif command.startswith("DOWNLOAD"):
#             if not authenticated:
#                 conn.sendall(b"ERROR: Authentication required")
#                 return

#             try:
#                 session_key = handle_key_exchange(conn, addr)
#                 print("[+] Key exchange successful")

#                 _, filename = command.split(maxsplit=1)
#                 filepath = os.path.join(SHARED_DIR, filename)
                
#                 if not os.path.exists(filepath):
#                     conn.sendall(b"ERROR: File not found")
#                     return

#                 with open(filepath, "rb") as f:
#                     plaintext = f.read()
                
#                 ciphertext = encrypt(plaintext, session_key)

#                 # Send file size
#                 size = len(ciphertext)
#                 conn.sendall(f"SIZE:{size}\n".encode())
                
#                 # Wait for client ready signal
#                 ready = conn.recv(5)
#                 if ready != b"READY":
#                     conn.sendall(b"ERROR: Client not ready")
#                     return

#                 # Send file in chunks
#                 sent = 0
#                 chunk_size = 8192
#                 while sent < size:
#                     chunk = ciphertext[sent:sent + chunk_size]
#                     conn.sendall(chunk)
#                     sent += len(chunk)
                
#                 print(f"[+] File '{filename}' sent to {addr}")
#                 return
                    
#             except Exception as e:
#                 print(f"[!] Download error: {e}")
#                 try:
#                     conn.sendall(f"ERROR: {str(e)}".encode())
#                 except:
#                     pass
#                 return

#         elif command.startswith("UPLOAD"):
#             if not authenticated:
#                 conn.sendall(b"ERROR: Authentication required\n")
#                 return

#             try:
#                 # 1. Perform key exchange first
#                 session_key = handle_key_exchange(conn, addr)
#                 print("[+] Key exchange successful")

#                 # 2. Get filename
#                 _, filename = command.split(maxsplit=1)
                
#                 # Validate filename
#                 if not filename.isprintable() or any(c in filename for c in '/\\'):
#                     conn.sendall(b"ERROR: Invalid filename\n")
#                     return

#                 # 3. Signal ready for file - ADD A SMALL DELAY HERE
#                 print("[SERVER DEBUG] Sending READY signal")
#                 # Add a small delay to ensure client can process messages separately
#                 time.sleep(0.2)  # 200ms delay to separate messages
#                 conn.sendall(b"READY\n")
#                 print("[SERVER DEBUG] READY signal sent")

#                 # 4. Get file size
#                 conn.settimeout(60)  # increase timeout to allow client enough time
#                 header = recv_until(conn, b"\n")
#                 if not header.startswith(b"SIZE:"):
#                     conn.sendall(b"ERROR: Invalid size header\n")
#                     return
                    
#                 try:
#                     file_size = int(header[len(b"SIZE:"):].strip())
#                 except ValueError:
#                     conn.sendall(b"ERROR: Invalid file size\n")
#                     return

#                 # 5. Receive file data
#                 received = 0
#                 ciphertext = b""
#                 while received < file_size:
#                     chunk = conn.recv(min(4096, file_size - received))
#                     if not chunk:
#                         raise ConnectionError("Connection closed during file transfer")
#                     ciphertext += chunk
#                     received += len(chunk)

#                 # 6. Decrypt and save file
#                 plaintext = decrypt(ciphertext, session_key)
#                 os.makedirs(SHARED_DIR, exist_ok=True)
#                 out_path = os.path.join(SHARED_DIR, filename)
                
#                 with open(out_path, "wb") as f:
#                     f.write(plaintext)

#                 # 7. Send confirmation
#                 conn.sendall(b"OK: File uploaded successfully\n")
#                 print(f"[+] File '{filename}' received from {addr}")
#                 return
                
#             except Exception as e:
#                 print(f"[!] Upload error: {e}")
#                 try:
#                     conn.sendall(f"ERROR: {str(e)}\n".encode())
#                 except:
#                     pass
#                 return

#         conn.sendall(b"ERROR: Unknown command")

#     except Exception as e:
#         print(f"[!] Error in peer handler: {e}")
#     finally:
#         conn.close()

# def start_peer_server(port):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.bind(("0.0.0.0", port))
#         s.listen()
#         print(f"[*] Peer server listening on port {port}...")
#         while True:
#             conn, addr = s.accept()
#             threading.Thread(
#                 target=handle_incoming_peer,
#                 args=(conn, addr),
#                 daemon=True
#             ).start()


# peer/server.py

import os
import socket
import threading
import time

from config import SHARED_DIR
from peer.auth import (
    register_user,
    authenticate_user,
    create_session_token,
    is_session_valid,
    renew_session
)
from peer.crypto_utils import (
    encrypt, 
    decrypt, 
    generate_dh_key_pair, 
    serialize_public_key, 
    deserialize_public_key, 
    derive_shared_secret
)
from peer.file_ops import list_shared_files


def handle_key_exchange(conn, addr):
    """Server-side key exchange with validation and debugging"""
    import traceback
    try:
        conn.settimeout(30)
        print(f"[DEBUG] Starting key exchange with {addr}")

        # 1. Generate DH keys
        print("[DEBUG] Generating DH keys...")
        dh_private, dh_public = generate_dh_key_pair()
        if not dh_private or not dh_public:
            raise ValueError("Invalid DH keys generated")

        # 2. Serialize and send server's public key
        print("[DEBUG] Serializing public key...")
        pubkey_bytes = serialize_public_key(dh_public)
        if not pubkey_bytes or len(pubkey_bytes) < 100:
            raise ValueError("Invalid public key serialization")

        print("[DEBUG] Sending server's public key...")
        conn.sendall(f"DH_PUBKEY:{len(pubkey_bytes)}\n".encode())
        time.sleep(0.1)  # Small delay to ensure header is sent separately
        conn.sendall(pubkey_bytes)

        # 3. Receive client's public key
        print("[DEBUG] Waiting for client's key header...")
        header = recv_until(conn, b"\n")
        print(f"[DEBUG] Received client header: {header}")
        
        if not header.startswith(b"CLIENT_PUBKEY:"):
            raise ValueError("Invalid client header format")

        try:
            key_size = int(header[len(b"CLIENT_PUBKEY:"):].strip())
            if key_size <= 0 or key_size > 10000:
                raise ValueError("Invalid client key size")
        except ValueError:
            raise ValueError("Malformed client key size")

        print(f"[DEBUG] Receiving client key (size: {key_size})...")
        client_key_bytes = recv_exact(conn, key_size)
        # Sanity check: make sure we received the correct number of bytes
        if len(client_key_bytes) != key_size:
            raise ValueError(f"Expected {key_size} bytes but got {len(client_key_bytes)}")

        # 4. Deserialize and verify client's public key
        print("[DEBUG] Deserializing client key...")
        print(f"[DEBUG] Client key bytes length: {len(client_key_bytes)}")

        try:
            client_pubkey = deserialize_public_key(client_key_bytes)
        except Exception as e:
            print("[DEBUG] Deserialization failed:", e)
            raise ValueError("Client public key deserialization failed")

        # 5. Derive shared secret
        print("[DEBUG] Deriving shared secret...")
        print("[DEBUG] Deserialization successful, computing shared secret...")

        shared_secret = derive_shared_secret(dh_private, client_pubkey)
        if not shared_secret or len(shared_secret) < 32:
            raise ValueError("Invalid shared secret derived")

        # 6. Send confirmation
        print("[DEBUG] Successfully derived shared secret, sending confirmation...")
        conn.sendall(b"KEY_EXCHANGE_COMPLETE\n")
        print("[DEBUG] Key exchange completed successfully")
        return shared_secret[:32]

    except Exception as e:
        print(f"[DEBUG] Key exchange failed: {e}")
        try:
            conn.sendall(b"KEY_EXCHANGE_FAILED\n")
        except Exception as send_err:
            print(f"[DEBUG] Failed to send KEY_EXCHANGE_FAILED: {send_err}")
        print("[DEBUG] Full exception traceback:")
        traceback.print_exc()
        raise


def recv_until(conn, delimiter):
    """Server-side receive until delimiter"""
    data = b""
    while delimiter not in data:
        chunk = conn.recv(1024)
        if not chunk:
            raise ConnectionError("Client disconnected")
        data += chunk
    return data


def recv_exact(conn, length):
    """Server-side receive exact bytes"""
    data = b""
    while len(data) < length:
        chunk = conn.recv(min(4096, length - len(data)))
        if not chunk:
            raise ConnectionError(f"Expected {length} bytes, got {len(data)}")
        data += chunk
    return data


def handle_incoming_peer(conn, addr):
    try:
        conn.settimeout(30)
        
        data = conn.recv(1024)
        if not data:
            return
        if data == b"PING":
            conn.sendall(b"PONG")
            return

        text = data.decode().strip()
        parts = text.split(maxsplit=1)
        authenticated = False
        token = ""
        if len(parts) >= 1:
            if len(parts[0]) == 32 and is_session_valid(parts[0]):
                token = parts[0]
                command = " ".join(parts[1:]) if len(parts) > 1 else ""
                authenticated = True
                renew_session(token)
            else:
                command = text

        # Authentication commands
        if command.startswith("REGISTER"):
            _, username, password = command.split(maxsplit=2)
            ok, msg = register_user(username, password)
            status = "OK" if ok else "ERROR"
            conn.sendall(f"{status}: {msg}".encode())
            return

        elif command.startswith("LOGIN"):
            _, username, password = command.split(maxsplit=2)
            if authenticate_user(username, password):
                token = create_session_token(username)
                conn.sendall(f"OK: {token}".encode())
            else:
                conn.sendall(b"ERROR: Invalid username or password")
            return

        # File operations
        if command == "LIST_FILES":
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required\n")
                return
            
            try:
                # First perform key exchange
                session_key = handle_key_exchange(conn, addr)
                print("[+] Key exchange successful")
                
                # Get file list
                files = list_shared_files()
                if not files:
                    conn.sendall(b"ERROR: No files available\n")
                    return
                
                # Encrypt the file list
                file_list = "\n".join(files).encode()
                ciphertext = encrypt(file_list, session_key)
                
                # Send the size header first
                size = len(ciphertext)
                conn.sendall(f"SIZE:{size}\n".encode())
                
                # Wait for client ready signal
                try:
                    ready = conn.recv(5)
                    if ready != b"READY":
                        conn.sendall(b"ERROR: Client not ready\n")
                        return
                except socket.timeout:
                    conn.sendall(b"ERROR: Client timeout waiting for READY\n")
                    return
                
                # Send the encrypted data
                conn.sendall(ciphertext)
                print(f"[+] Sent file list to {addr}")
                return
                    
            except Exception as e:
                print(f"[!] LIST_FILES error: {e}")
                try:
                    conn.sendall(f"ERROR: {str(e)}\n".encode())
                except:
                    pass
                return

        elif command.startswith("DOWNLOAD"):
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required\n")
                return

            try:
                # Parse filename
                _, filename = command.split(maxsplit=1)
                filepath = os.path.join(SHARED_DIR, filename)
                
                if not os.path.exists(filepath):
                    conn.sendall(b"ERROR: File not found\n")
                    return
                
                # Perform key exchange
                session_key = handle_key_exchange(conn, addr)
                print("[+] Key exchange successful")

                # Read and encrypt file
                with open(filepath, "rb") as f:
                    plaintext = f.read()
                
                ciphertext = encrypt(plaintext, session_key)

                # Send file size
                size = len(ciphertext)
                conn.sendall(f"SIZE:{size}\n".encode())
                
                # Wait for client ready signal
                ready = conn.recv(8)  # Expect "READY\n"
                if not ready.startswith(b"READY"):
                    conn.sendall(b"ERROR: Client not ready\n")
                    return

                # Send file in chunks
                sent = 0
                chunk_size = 8192
                while sent < size:
                    chunk = ciphertext[sent:sent + chunk_size]
                    conn.sendall(chunk)
                    sent += len(chunk)
                
                print(f"[+] File '{filename}' sent to {addr}")
                return
                    
            except Exception as e:
                print(f"[!] Download error: {e}")
                try:
                    conn.sendall(f"ERROR: {str(e)}\n".encode())
                except:
                    pass
                return

        elif command.startswith("UPLOAD"):
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required\n")
                return

            try:
                # 1. Perform key exchange first
                session_key = handle_key_exchange(conn, addr)
                print("[+] Key exchange successful")

                # 2. Get filename
                _, filename = command.split(maxsplit=1)
                
                # Validate filename
                if not filename.isprintable() or any(c in filename for c in '/\\'):
                    conn.sendall(b"ERROR: Invalid filename\n")
                    return

                # 3. Signal ready for file - ADD A SMALL DELAY HERE
                print("[SERVER DEBUG] Sending READY signal")
                # Add a small delay to ensure client can process messages separately
                time.sleep(0.2)  # 200ms delay to separate messages
                conn.sendall(b"READY\n")
                print("[SERVER DEBUG] READY signal sent")

                # 4. Get file size
                conn.settimeout(60)  # increase timeout to allow client enough time
                header = recv_until(conn, b"\n")
                if not header.startswith(b"SIZE:"):
                    conn.sendall(b"ERROR: Invalid size header\n")
                    return
                    
                try:
                    file_size = int(header[len(b"SIZE:"):].strip())
                except ValueError:
                    conn.sendall(b"ERROR: Invalid file size\n")
                    return

                # 5. Receive file data
                received = 0
                ciphertext = b""
                while received < file_size:
                    chunk = conn.recv(min(4096, file_size - received))
                    if not chunk:
                        raise ConnectionError("Connection closed during file transfer")
                    ciphertext += chunk
                    received += len(chunk)

                # 6. Decrypt and save file
                plaintext = decrypt(ciphertext, session_key)
                os.makedirs(SHARED_DIR, exist_ok=True)
                out_path = os.path.join(SHARED_DIR, filename)
                
                with open(out_path, "wb") as f:
                    f.write(plaintext)

                # 7. Send confirmation
                conn.sendall(b"OK: File uploaded successfully\n")
                print(f"[+] File '{filename}' received from {addr}")
                return
                
            except Exception as e:
                print(f"[!] Upload error: {e}")
                try:
                    conn.sendall(f"ERROR: {str(e)}\n".encode())
                except:
                    pass
                return

        conn.sendall(b"ERROR: Unknown command\n")

    except Exception as e:
        print(f"[!] Error in peer handler: {e}")
    finally:
        conn.close()


def start_peer_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen()
        print(f"[*] Peer server listening on port {port}...")
        while True:
            conn, addr = s.accept()
            threading.Thread(
                target=handle_incoming_peer,
                args=(conn, addr),
                daemon=True
            ).start()