import threading
import socket
from config          import DISCOVERY_PORT, TCP_DEFAULT_PORT
from peer.server     import start_peer_server
from peer.client     import peer_client_menu
from peer.discovery  import respond_to_discovery, discover_peers

def main():
    # 1) Choose your TCP port
    port = input(f"Enter your peer server port [{TCP_DEFAULT_PORT}]: ").strip()
    try:
        port = int(port) if port else TCP_DEFAULT_PORT
    except ValueError:
        port = TCP_DEFAULT_PORT

    # 2) Start your file-share server
    threading.Thread(target=start_peer_server, args=(port,), daemon=True).start()
    print(f"[*] Peer server listening on TCP port {port}")

    # 3) Start the discovery responder
    threading.Thread(target=respond_to_discovery, args=(port,), daemon=True).start()
    print(f"[*] Discovery responder listening on UDP port {DISCOVERY_PORT}")

    # 4) Probe the LAN to find peers
    print("[*] Broadcasting on LAN to find peers…")
    peers = discover_peers(timeout=2.0)
    print(f"[+] Discovered peers: {peers}")

    # 5) Enter your interactive CLI
    peer_client_menu(peers)

if __name__ == "__main__":
    main()
