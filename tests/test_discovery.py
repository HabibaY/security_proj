import pytest
from unittest.mock import patch, MagicMock, call
from peer.discovery import discover_peers, respond_to_discovery
import socket
from config import DISCOVERY_PORT

@pytest.fixture
def mock_socket():
    with patch('socket.socket') as mock_socket:
        yield mock_socket

def test_discover_peers(mock_socket):
    """Test peer discovery with mock responses"""
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance
    
    # Configure mock responses
    mock_sock_instance.recvfrom.side_effect = [
        (b'CIPHERSHARE_PEER 5000', ('192.168.1.2', 12345)),
        socket.timeout()  # Simulate timeout to end loop
    ]
    
    peers = discover_peers(timeout=0.1)
    assert len(peers) == 1
    assert ('192.168.1.2', 5000) in peers
    
    # Verify socket setup and broadcast
    mock_sock_instance.setsockopt.assert_called_once_with(
        socket.SOL_SOCKET, socket.SO_BROADCAST, 1
    )
    mock_sock_instance.sendto.assert_called_once_with(
        b'CIPHERSHARE_DISCOVERY',
        ('<broadcast>', DISCOVERY_PORT)
    )
    mock_sock_instance.settimeout.assert_called_once_with(0.1)

def test_respond_to_discovery(mock_socket):
    """Test discovery response daemon"""
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance
    
    # Configure mock request and simulate one iteration
    mock_sock_instance.recvfrom.side_effect = [
        (b'CIPHERSHARE_DISCOVERY', ('192.168.1.1', 12345)),
        Exception("Break infinite loop")  # Force exit
    ]
    
    # Test with try-except to handle our forced exit
    try:
        respond_to_discovery(5000)
    except Exception as e:
        if str(e) != "Break infinite loop":
            raise
    
    # Verify socket setup and response
    mock_sock_instance.setsockopt.assert_called_once_with(
        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
    )
    mock_sock_instance.bind.assert_called_once_with(('', DISCOVERY_PORT))
    mock_sock_instance.sendto.assert_called_once_with(
        b'CIPHERSHARE_PEER 5000',
        ('192.168.1.1', 12345)
    )

