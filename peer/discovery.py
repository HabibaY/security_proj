import socket
import time
from config import DISCOVERY_PORT

DISCOVER_REQUEST = b"CIPHERSHARE_DISCOVERY"
DISCOVER_REPLY   = b"CIPHERSHARE_PEER"

def respond_to_discovery(tcp_port):
    """Daemon thread: listen for discovery broadcasts and reply with your TCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', DISCOVERY_PORT))
    while True:
        data, addr = sock.recvfrom(1024)
        if data == DISCOVER_REQUEST:
            reply = DISCOVER_REPLY + b" " + str(tcp_port).encode()
            sock.sendto(reply, addr)

def discover_peers(timeout=2.0):
    """Broadcast a discovery request, collect replies for `timeout` seconds."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    # send broadcast
    sock.sendto(DISCOVER_REQUEST, ('<broadcast>', DISCOVERY_PORT))

    peers = set()
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            break
        if data.startswith(DISCOVER_REPLY):
            parts = data.split()
            if len(parts) == 2:
                peer_port = int(parts[1])
                peers.add((addr[0], peer_port))

    sock.close()
    return list(peers)
