
import os
import socket
import tkinter as tk
from tkinter import filedialog
from config import RECEIVED_DIR, DISCOVERY_PORT
from peer.discovery import discover_peers
from peer.crypto_utils import (
    generate_dh_key_pair,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_secret
)
import time
from peer.client_storage import ClientAuthStore


def peer_client_menu(peers):
    # Dictionary to store session tokens for each peer
    session_tokens = {}

    while True:
        # 1) Prune any peers that have gone offline
        active_peers = []
        for ip, port in peers:
            if check_peer_alive(ip, port):
                active_peers.append((ip, port))
        peers = active_peers

        if not peers:
            print("[!] No active peers available.")
        else:
            print(f"[*] {len(peers)} peer(s) online.")

        # 2) Show menu
        print("\n=== Peer Client Menu ===")
        print("1. Login/Register to a peer")
        print("2. List files on a peer")
        print("3. Download file from a peer")
        print("4. Upload file to a peer")
        print("5. Discover peers on LAN")
        print("6. Exit")

        choice = input("Select an option (1-6): ").strip()

        # 3) Exit
        if choice == "6":
            break

        # 4) Manual discovery
        if choice == "5":
            print(f"[*] Broadcasting discovery on UDP port {DISCOVERY_PORT}...")
            new_peers = discover_peers(timeout=2.0)
            if new_peers:
                print(f"[+] Found peers: {new_peers}")
                for p in new_peers:
                    if p not in peers:
                        peers.append(p)
            else:
                print("[*] No new peers found.")
            continue  # back to top of loop

        # 5) Actions 1-4 require selecting a peer
        if choice not in {"1", "2", "3", "4"}:
            continue

        peer_ip, peer_port = select_peer(peers)
        if peer_ip is None:
            continue

        # 6) Perform the chosen action
        if choice == "1":
            token = authenticate_with_peer(peer_ip, peer_port)
            if token:
                session_tokens[(peer_ip, peer_port)] = token
                print(f"[+] Authentication successful! Token stored for {peer_ip}:{peer_port}")
        else:
            token = session_tokens.get((peer_ip, peer_port))
            if not token:
                print("[!] Please login/register to this peer first!")
                continue

            if choice == "2":
                list_files(peer_ip, peer_port, token)
            elif choice == "3":
                # First list files to select one
                files = list_files(peer_ip, peer_port, token)
                if not files:
                    continue
                    
                try:
                    file_idx = int(input("\nEnter file number to download (0 to cancel): ").strip()) - 1
                    if file_idx < 0:
                        print("Download cancelled")
                        continue
                    if file_idx >= len(files):
                        print("[!] Invalid file number")
                        continue
                        
                    filename = files[file_idx]
                    download_file(peer_ip, peer_port, token, filename)
                except ValueError:
                    print("[!] Invalid selection")
                    
            elif choice == "4":
                upload_file(peer_ip, peer_port, token)


def select_peer(peers):
    if not peers:
        print("[!] No peers available.")
        return None, None
        
    # Show only active peers
    active_peers = []
    for ip, port in peers:
        if check_peer_alive(ip, port):
            active_peers.append((ip, port))
            print(f"{len(active_peers)}. {ip}:{port} (ONLINE)")
        else:
            print(f"X. {ip}:{port} (OFFLINE)")
            
    if not active_peers:
        print("[!] No active peers available")
        return None, None
        
    try:
        idx = int(input("Select peer number: ").strip()) - 1
        if idx < 0 or idx >= len(active_peers):
            print("[!] Invalid selection")
            return None, None
        return active_peers[idx]
    except (ValueError, IndexError):
        print("[!] Invalid selection")
        return None, None


def authenticate_with_peer(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=10) as s:
            print("\n--- Authentication ---")
            print("1) Login\n2) Register")
            choice = input("Option: ").strip()
            
            if choice not in ["1", "2"]:
                print("[!] Invalid choice. Please select 1 for Login or 2 for Register.")
                return None
                
            user = input("Username: ").strip()
            pwd = input("Password: ").strip()
            
            cmd = "LOGIN" if choice == "1" else "REGISTER"
            s.sendall(f"{cmd} {user} {pwd}".encode())

            response = s.recv(1024).decode().strip()

            if choice == "2":  # Registration
                if response.startswith("OK:"):
                    print("[+] Registration successful. Please log in.")
                else:
                    print(f"[-] Registration failed: {response}")
                return None  # Don't expect token on registration
            else:  # Login
                if response.startswith("OK:"):
                    token = response.split("OK:")[1].strip()
                    if len(token) == 32:
                        print("[+] Authentication successful!")
                        return token
                    else:
                        print("[-] Invalid token received from server")
                        return None
                else:
                    print(f"[-] Authentication failed: {response}")
                    return None

    except Exception as e:
        print(f"[-] Connection error: {e}")
        return None


def list_files(ip, port, token):
    try:
        with socket.create_connection((ip, port), timeout=30) as sock:
            # 1. First send the authenticated command
            sock.sendall(f"{token} LIST_FILES\n".encode())
            
            # 2. Then perform key exchange
            session_key, extra_data = perform_key_exchange(sock)
            print("[+] Key exchange successful")

            # 3. Check if we already received SIZE header in extra_data
            if extra_data and b"SIZE:" in extra_data:
                # Split into lines
                lines = extra_data.split(b"\n")
                for line in lines:
                    if line.startswith(b"SIZE:"):
                        size_header = line.decode().strip()
                        break
                # Send READY immediately
                sock.sendall(b"READY")
            else:
                # 4. Receive response or error
                response = recv_until(sock, b"\n").decode().strip()
                if response.startswith("ERROR:"):
                    print(f"[-] {response}")
                    return []

                # 5. Receive size header
                size_header = recv_until(sock, b"\n").decode().strip()
                if not size_header.startswith("SIZE:"):
                    print("[-] Invalid size header received")
                    return []

                # 6. Send ready signal
                sock.sendall(b"READY")

            try:
                filesize = int(size_header[5:])
            except ValueError:
                print("[-] Invalid file size format")
                return []

            # 7. Receive encrypted data
            encrypted_data = b""
            remaining = filesize
            while remaining > 0:
                chunk = sock.recv(min(4096, remaining))
                if not chunk:
                    break
                encrypted_data += chunk
                remaining -= len(chunk)

            # 8. Decrypt
            from peer.crypto_utils import decrypt
            try:
                plaintext = decrypt(encrypted_data, session_key)
                file_list = plaintext.decode().strip().splitlines()
            except Exception as e:
                print(f"[-] Decryption failed: {e}")
                return []

            if not file_list:
                print("[-] No files available on the peer.")
                return []

            print("[+] Files available on peer:\n")
            for i, fname in enumerate(file_list, 1):
                print(f"{i}. {fname}")
            return file_list

    except Exception as e:
        print("[-] List files failed:", str(e))
        return []


def download_file(ip, port, token, filename):
    try:
        with socket.create_connection((ip, port), timeout=30) as sock:
            # First send download command with token
            sock.sendall(f"{token} DOWNLOAD {filename}\n".encode())
            
            # Then perform key exchange
            session_key, extra_data = perform_key_exchange(sock)
            print("[+] Key exchange successful")
            
            # Check if we already received SIZE header in extra_data
            size_header = None
            if extra_data and b"SIZE:" in extra_data:
                # Split into lines to find the SIZE header
                lines = extra_data.split(b"\n")
                for line in lines:
                    if line.startswith(b"SIZE:"):
                        size_header = line.decode().strip()
                        break
            
            # If we didn't get SIZE header in extra_data, receive it normally
            if not size_header:
                # Receive response or error
                response = recv_until(sock, b"\n").decode().strip()
                if response.startswith("ERROR:"):
                    print(f"[-] {response}")
                    return None
                
                # Receive size header
                size_header = recv_until(sock, b"\n").decode().strip()
                if not size_header.startswith("SIZE:"):
                    print("[-] Invalid size header")
                    return None
            
            # Parse file size
            try:
                filesize = int(size_header[5:])
            except ValueError:
                print("[-] Invalid file size format")
                return None
                
            # Send ready signal with newline
            sock.sendall(b"READY\n")
            
            # Receive file data
            received = 0
            ciphertext = b""
            while received < filesize:
                chunk = sock.recv(min(8192, filesize - received))
                if not chunk:
                    break
                ciphertext += chunk
                received += len(chunk)
                print(f"\r{received}/{filesize} bytes ({received/filesize:.1%})", end="", flush=True)
            
            # Decrypt and save file
            from peer.crypto_utils import decrypt
            try:
                plaintext = decrypt(ciphertext, session_key)
                os.makedirs(RECEIVED_DIR, exist_ok=True)
                out_path = os.path.join(RECEIVED_DIR, filename)
                with open(out_path, "wb") as f:
                    f.write(plaintext)
                print(f"\n[+] File saved to {out_path}")
                return out_path
            except Exception as e:
                print(f"\n[-] Decryption failed: {e}")
                return None

    except Exception as e:
        print(f"\n[-] Download failed: {e}")
        return None

def upload_file(ip, port, token):
    # --- bring up a hidden Tk root so dialogs work reliably ---
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    root.update()

    filepath = filedialog.askopenfilename(title="Select file to upload")
    root.destroy()  
    if not filepath:
        print("Upload cancelled or failed")
        return

    filename = os.path.basename(filepath)
    print(f"[*] Reading file: {filepath}")
    
    with open(filepath, "rb") as f:
        plaintext = f.read()

    print(f"[*] Preparing to encrypt {len(plaintext)} bytes...")
    
    try:
        print(f"[DEBUG] Connecting to {ip}:{port}...")
        with socket.create_connection((ip, port), timeout=60) as s:
            # Send UPLOAD command with token
            print("[DEBUG] Sending UPLOAD command...")
            upload_cmd = f"{token} UPLOAD {filename}\n"  # Explicit newline
            s.sendall(upload_cmd.encode())
            print(f"[DEBUG] Sent command: {upload_cmd.strip()}")

            # Wait for server to initiate key exchange
            try:
                print("[DEBUG] Starting key exchange...")
                session_key, extra_data = perform_key_exchange(s)
                print("[+] Key exchange successful")
            except Exception as e:
                print(f"[-] Key exchange failed: {e}")
                return

            # Check if READY was already received in the extra_data
            ready_received = False
            if extra_data and b"\n" in extra_data:
                lines = extra_data.split(b"\n")
                # Check if we received READY in the same packet as KEY_EXCHANGE_COMPLETE
                for i in range(1, len(lines)):  # Start from index 1 to skip KEY_EXCHANGE_COMPLETE
                    if lines[i].strip() == b"READY":
                        ready_received = True
                        print("[DEBUG] Found READY signal in the key exchange response")
                        break

            # Only wait for READY if we haven't received it yet
            if not ready_received:
                print("[DEBUG] Waiting for server READY signal...")
                try:
                    ready_response = recv_until(s, b"\n", timeout=60)
                    ready_line = ready_response.strip()
                    
                    if ready_line != b"READY":
                        print(f"[-] Unexpected server response: {ready_response}")
                        return
                    
                    print("[DEBUG] Server is ready for file transfer")
                except socket.timeout:
                    print("[DEBUG] Timeout waiting for READY signal")
                    raise
            
            # Encrypt and send file
            from peer.crypto_utils import encrypt
            print("[DEBUG] Encrypting file...")
            ciphertext = encrypt(plaintext, session_key)
            print(f"[*] Uploading {len(ciphertext)} bytes...")

            # Send size header
            print("[DEBUG] Sending file size header...")
            size_header = f"SIZE:{len(ciphertext)}\n"
            s.sendall(size_header.encode())
            print(f"[DEBUG] Sent size header: {size_header.strip()}")
            # Send file in chunks with progress updates
            sent = 0
            total = len(ciphertext)
            chunk_size = 8192
            print("[DEBUG] Starting file transfer...")
            while sent < total:
                chunk = ciphertext[sent:sent + chunk_size]
                try:
                    bytes_sent = s.send(chunk)
                    if bytes_sent == 0:
                        raise ConnectionError("Connection broken during transfer")
                    sent += bytes_sent
                    print(f"\r{sent}/{total} bytes ({sent/total:.1%})", end="", flush=True)
                except Exception as e:
                    print(f"\n[DEBUG] Error during transfer: {e}")
                    raise

            print("\n[*] Waiting for confirmation...")
            print("[DEBUG] Waiting for server response...")

            # Get final response
            response = recv_until(s, b"\n").decode().strip()
            print(f"[DEBUG] Server response: {response}")
            if response.startswith("OK:"):
                print(f"[+] Upload successful: {response}")
            else:
                print(f"[-] Upload failed: {response}")

    except socket.timeout as e:
        print(f"[-] Upload timeout: {e}")
    except ConnectionError as e:
        print(f"[-] Connection error: {e}")
    except Exception as e:
        print(f"[-] Upload error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        
# def perform_key_exchange(sock, send_init=True):
#     """Robust DH key exchange with full validation"""
#     try:
#         sock.settimeout(30)
        
#         print("[DEBUG] Starting key exchange...")
        
#         # 1. Generate and validate DH keys
#         print("[DEBUG] Generating DH keys...")
#         dh_private, dh_public = generate_dh_key_pair()
#         if not dh_private or not dh_public:
#             raise ValueError("Invalid DH keys generated")
            
#         pubkey_bytes = serialize_public_key(dh_public)
#         if not pubkey_bytes or len(pubkey_bytes) < 100:
#             raise ValueError("Invalid public key serialization")

#         # 2. Receive server's key
#         print("[DEBUG] Waiting for server's key header...")
#         header = b""
#         while b"\n" not in header:
#             chunk = sock.recv(1024)
#             if not chunk:
#                 raise ConnectionError("Connection closed while reading header")
#             header += chunk
            
#         print(f"[DEBUG] Received header: {header}")
        
#         if not header.startswith(b"DH_PUBKEY:"):
#             if header.startswith(b"KEY_EXCHANGE_FAILED"):
#                 raise ValueError("Server reported key exchange failure")
#             raise ValueError(f"Invalid server header format: {header}")

#         # 3. Parse key size
#         try:
#             key_size_part = header[:header.index(b"\n")].decode('utf-8', errors='replace')
#             print(f"[DEBUG] Key size part: {key_size_part}")
#             key_size = int(key_size_part[len("DH_PUBKEY:"):].strip())
#             if key_size <= 0 or key_size > 10000:
#                 raise ValueError("Invalid key size")
#         except ValueError as e:
#             raise ValueError(f"Malformed key size header: {e}")

#         # 4. Receive full key
#         print(f"[DEBUG] Receiving server key (size: {key_size})...")
#         server_key_bytes = b""
#         remaining = key_size
#         while remaining > 0:
#             chunk = sock.recv(min(4096, remaining))
#             if not chunk:
#                 raise ConnectionError(f"Incomplete key (got {len(server_key_bytes)}/{key_size} bytes)")
#             server_key_bytes += chunk
#             remaining -= len(chunk)

#         # 5. Send client's key
#         print("[DEBUG] Sending client's public key...")
#         sock.sendall(f"CLIENT_PUBKEY:{len(pubkey_bytes)}\n".encode())
#         time.sleep(0.1)
#         sock.sendall(pubkey_bytes)
#         time.sleep(0.05)

#         # 6. Verify completion
#         print("[DEBUG] Waiting for key exchange completion...")
#         completion_data = b""
#         while b"\n" not in completion_data:
#             chunk = sock.recv(1024)
#             if not chunk:
#                 raise ConnectionError("Connection closed during completion verification")
#             completion_data += chunk
            
#         response_text = completion_data.split(b"\n")[0].decode('utf-8', errors='replace')
#         print(f"[DEBUG] Server completion raw data: {completion_data}")
#         print(f"[DEBUG] Received completion response: {response_text}")
        
#         if response_text != "KEY_EXCHANGE_COMPLETE":
#             raise ValueError(f"Key exchange not completed, got: {response_text}")

#         # 7. Validate and derive shared secret
#         print("[DEBUG] Deriving shared secret...")
#         try:
#             server_pubkey = deserialize_public_key(server_key_bytes)
#             if not server_pubkey:
#                 raise ValueError("Failed to deserialize server key")
                
#             shared_secret = derive_shared_secret(dh_private, server_pubkey)
#             if not shared_secret or len(shared_secret) < 32:
#                 raise ValueError("Invalid shared secret derived")
    
#             print("[DEBUG] Key exchange successful!")
#             return shared_secret[:32]
#         except Exception as e:
#             raise ValueError(f"Key derivation failed: {e}")
        
#     except Exception as e:
#         print(f"[DEBUG] Key exchange failed at step: {type(e).__name__}: {str(e)}")
#         raise

# client.py (updated perform_key_exchange function)
def perform_key_exchange(sock, send_init=True):
    """Robust DH key exchange with full validation"""
    try:
        sock.settimeout(30)
        
        print("[DEBUG] Starting key exchange...")
        
        # 1. Generate and validate DH keys
        print("[DEBUG] Generating DH keys...")
        dh_private, dh_public = generate_dh_key_pair()
        if not dh_private or not dh_public:
            raise ValueError("Invalid DH keys generated")
            
        pubkey_bytes = serialize_public_key(dh_public)
        if not pubkey_bytes or len(pubkey_bytes) < 100:
            raise ValueError("Invalid public key serialization")

        # 2. Receive server's key header
        print("[DEBUG] Waiting for server's key header...")
        header = b""
        while b"\n" not in header:
            chunk = sock.recv(1024)
            if not chunk:
                raise ConnectionError("Connection closed while reading header")
            header += chunk
                
        print(f"[DEBUG] Received header: {header}")
        
        if not header.startswith(b"DH_PUBKEY:"):
            if header.startswith(b"KEY_EXCHANGE_FAILED"):
                raise ValueError("Server reported key exchange failure")
            if header.startswith(b"ERROR:"):
                raise ValueError(f"Server error: {header.decode().strip()}")
            raise ValueError(f"Invalid server header format: {header}")

        # 3. Parse key size
        try:
            key_size_part = header[:header.index(b"\n")].decode('utf-8', errors='replace')
            print(f"[DEBUG] Key size part: {key_size_part}")
            key_size = int(key_size_part[len("DH_PUBKEY:"):].strip())
            if key_size <= 0 or key_size > 10000:
                raise ValueError("Invalid key size")
        except ValueError as e:
            raise ValueError(f"Malformed key size header: {e}")

        # 4. Receive full key
        print(f"[DEBUG] Receiving server key (size: {key_size})...")
        server_key_bytes = header[header.index(b"\n")+1:]  # Get any remaining data after header
        remaining = key_size - len(server_key_bytes)
        
        while remaining > 0:
            chunk = sock.recv(min(4096, remaining))
            if not chunk:
                raise ConnectionError(f"Incomplete key (got {len(server_key_bytes)}/{key_size} bytes)")
            server_key_bytes += chunk
            remaining -= len(chunk)

        # 5. Send client's key
        print("[DEBUG] Sending client's public key...")
        sock.sendall(f"CLIENT_PUBKEY:{len(pubkey_bytes)}\n".encode())
        time.sleep(0.1)  # Small delay to ensure separate packets
        sock.sendall(pubkey_bytes)
        time.sleep(0.1)  # Small delay before next operation

        # 6. Verify completion
        print("[DEBUG] Waiting for key exchange completion...")
        completion_data = b""
        while b"\n" not in completion_data:
            chunk = sock.recv(1024)
            if not chunk:
                raise ConnectionError("Connection closed during completion verification")
            completion_data += chunk
                
        # Get first line for completion check
        completion_lines = completion_data.split(b"\n")
        response_text = completion_lines[0].decode('utf-8', errors='replace')
        print(f"[DEBUG] Server completion raw data: {completion_data}")
        print(f"[DEBUG] Received completion response: {response_text}")
        
        if response_text != "KEY_EXCHANGE_COMPLETE":
            raise ValueError(f"Key exchange not completed, got: {response_text}")

        # 7. Validate and derive shared secret
        print("[DEBUG] Deriving shared secret...")
        try:
            server_pubkey = deserialize_public_key(server_key_bytes)
            if not server_pubkey:
                raise ValueError("Failed to deserialize server key")
                
            shared_secret = derive_shared_secret(dh_private, server_pubkey)
            if not shared_secret or len(shared_secret) < 32:
                raise ValueError("Invalid shared secret derived")
    
            print("[DEBUG] Key exchange successful!")
            
            # Get any extra data received after the KEY_EXCHANGE_COMPLETE line
            extra_data = b""
            if len(completion_lines) > 1:
                extra_data = b"\n".join(completion_lines[1:])
            
            # Return both the shared secret and any extra data received
            return shared_secret[:32], extra_data
        except Exception as e:
            raise ValueError(f"Key derivation failed: {e}")
        
    except Exception as e:
        print(f"[DEBUG] Key exchange failed at step: {type(e).__name__}: {str(e)}")
        raise


def recv_until(sock, delimiter, timeout=30):
    data = b""
    sock.settimeout(timeout)
    start_time = time.time()
    
    while delimiter not in data:
        # Check if we've exceeded timeout
        if timeout and time.time() - start_time > timeout:
            raise socket.timeout("Timeout while receiving data")
            
        try:
            chunk = sock.recv(1024)
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        except socket.timeout:
            if time.time() - start_time > timeout:
                raise
            continue
            
    parts = data.split(delimiter, 1)
    result = parts[0] + delimiter
    remaining = parts[1] if len(parts) > 1 else b""
    return result

def select_file_dialog():
    try:
        root = tk.Tk()
        root.withdraw()
        filepath = filedialog.askopenfilename(title="Select file to upload")
        root.destroy()
        return filepath
    except Exception as e:
        print(f"[!] File dialog error: {e}")
        return None


def check_peer_alive(ip, port):
    """Check if a peer is still responsive"""
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(b"PING")
            try:
                response = s.recv(4)
                return response == b"PONG"
            except socket.timeout:
                return False
    except (socket.timeout, ConnectionRefusedError, OSError):
        print(f"[-] Failed to connect to peer {ip}:{port}")
        return False