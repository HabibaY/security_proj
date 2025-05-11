import os
import pytest
from unittest.mock import patch, MagicMock, mock_open
from peer.client import (
    peer_client_menu,
    download_file,
    upload_file,
    list_files,
    authenticate_with_peer,
    check_peer_alive,
    select_peer
)
from peer.server import handle_incoming_peer
import socket
import threading

# Test constants
TEST_PORT = 5050
TEST_TOKEN = "testtoken" * 4  # 32 chars
TEST_USER = "testuser"
TEST_PASS = "testpass123"

@pytest.fixture
def mock_server():
    """Fixture to set up a mock server thread"""
    with patch('peer.server.socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        
        # Create a mock connection for the server to handle
        mock_client_conn = MagicMock()
        mock_sock_instance.accept.return_value = (mock_client_conn, ('127.0.0.1', 12345))
        
        # Start the server in a thread
        server_thread = threading.Thread(
            target=handle_incoming_peer,
            args=(mock_client_conn, ('127.0.0.1', 12345)),
            daemon=True
        )
        server_thread.start()
        
        yield mock_sock_instance, mock_client_conn
        
        # Cleanup
        server_thread.join(timeout=1)

@pytest.fixture
def mock_peers():
    return [("127.0.0.1", 5050), ("192.168.1.2", 5051)]

def test_authenticate_with_peer_success(mock_server):
    mock_server_sock, mock_server_conn = mock_server
    mock_server_conn.recv.side_effect = [
        f"OK: {TEST_TOKEN}".encode(),  # Login response
        b"file1.txt\nfile2.txt"        # Subsequent list files response
    ]
    
    # Mock the socket connection properly
    with patch('peer.client.socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.recv.return_value = f"OK: {TEST_TOKEN}".encode()
        
        with patch('builtins.input', side_effect=["1", TEST_USER, TEST_PASS]):
            token = authenticate_with_peer("127.0.0.1", TEST_PORT)
            assert token == TEST_TOKEN

def test_list_files_success(mock_server):
    mock_server_sock, mock_server_conn = mock_server
    
    # Mock the client socket connection
    with patch('peer.client.socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.recv.return_value = b"file1.txt\nfile2.txt"
        
        with patch('builtins.print') as mock_print:
            list_files("127.0.0.1", TEST_PORT, TEST_TOKEN)
            
            # Verify the command was sent
            mock_sock_instance.sendall.assert_called_with(
                f"{TEST_TOKEN} LIST_FILES".encode()
            )
            mock_print.assert_called_with("\nfile1.txt\nfile2.txt")

def test_download_file_success(mock_server):
    """Test for successful file download that's compatible with the download_file implementation."""
    
    # In the download_file function, we need to simulate:
    # 1. Creating a socket to get the file list
    # 2. Creating another socket to download the file
    # 3. Socket returning the SIZE header first, then the content
    
    # First, let's patch socket creation
    with patch('peer.client.socket.socket') as mock_socket_class, \
         patch('peer.client.socket.create_connection') as mock_create_connection:
         
        # When the code creates a socket connection in download_file
        mock_socket1 = MagicMock(name="connection1")
        mock_socket2 = MagicMock(name="connection2")
        
        # Set up the create_connection to return our mock sockets
        mock_create_connection.side_effect = [mock_socket1, mock_socket2]
        
        # Set up the context manager behavior
        mock_socket1.__enter__.return_value = mock_socket1
        mock_socket1.__exit__.return_value = None
        mock_socket2.__enter__.return_value = mock_socket2
        mock_socket2.__exit__.return_value = None
        
        # Set up the first socket to return a file list
        mock_socket1.recv.return_value = b"file1.txt\nfile2.txt"
        
        # Set up the second socket to handle the SIZE header and content bytes
        # In the download_file function, it reads the header byte by byte until \n
        # For simplicity, we'll simulate the complete SIZE header in one response
        mock_socket2.recv.side_effect = [
            b"SIZE:100\n",  # First response is the SIZE header
            b"x" * 100      # Second response is the full encrypted content
        ]
        
        # Patch various file operations and user input
        with patch('builtins.input', return_value="1"), \
             patch('peer.client.decrypt', return_value=b"file_content"), \
             patch('peer.client.os.makedirs', return_value=None), \
             patch('peer.client.os.path.join', return_value="received/file1.txt"), \
             patch('builtins.open', mock_open()) as mock_file, \
             patch('builtins.print'):
            
            # Call the download_file function
            result = download_file("127.0.0.1", TEST_PORT, TEST_TOKEN)
            
            # The function should return the path to the saved file
            assert result == "received/file1.txt"
            
            # Verify the file was written with the decrypted content
            mock_file().write.assert_called_once_with(b"file_content")
            
            # Verify the READY signal was sent to request the file data
            mock_socket2.sendall.assert_called_with(b"READY")

def test_download_file_failure(mock_server):
    # Mock the client socket connection
    with patch('peer.client.socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        # Simulate no files available response
        mock_sock_instance.recv.return_value = b"No files available"
        
        with patch('builtins.input', return_value="1"), \
             patch('builtins.print') as mock_print:
            
            result = download_file("127.0.0.1", TEST_PORT, TEST_TOKEN)
            assert result is None
            # Check if the expected message was printed at any point
            assert any("No files available" in str(call) 
                   for call in mock_print.call_args_list)

def test_upload_file_success(mock_server):
    # Mock the client socket connection
    with patch('peer.client.socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.recv.side_effect = [
            b"READY",
            b"OK: File uploaded successfully"
        ]
        
        # Mock file operations
        with patch('peer.client.filedialog.askopenfilename', return_value="/path/to/test.txt"), \
             patch('peer.client.open', mock_open(read_data=b"test content")), \
             patch('peer.client.os.path.basename', return_value="test.txt"), \
             patch('peer.client.encrypt', return_value=b"encrypted"), \
             patch('builtins.print') as mock_print:
            
            upload_file("127.0.0.1", TEST_PORT, TEST_TOKEN)
            
            # Verify the upload command was sent
            mock_sock_instance.sendall.assert_any_call(
                f"{TEST_TOKEN} UPLOAD test.txt".encode()
            )
            mock_print.assert_called_with("[+] File 'test.txt' uploaded successfully")

def test_check_peer_alive_success():
    with patch('peer.client.socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.recv.return_value = b"PONG"
        
        assert check_peer_alive("127.0.0.1", TEST_PORT) is True

def test_check_peer_alive_failure():
    """Test failed peer alive check"""
    with patch('socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.connect.side_effect = ConnectionRefusedError
        
        assert check_peer_alive("127.0.0.1", TEST_PORT) is False

def test_select_peer_valid(mock_peers):
    with patch('builtins.input', return_value="1"), \
         patch('peer.client.check_peer_alive', side_effect=[True, True]), \
         patch('builtins.print'):
        
        ip, port = select_peer(mock_peers)
        assert ip == "127.0.0.1"
        assert port == 5050

def test_select_peer_invalid(mock_peers):
    """Test invalid peer selection"""
    with patch('builtins.input', return_value="3"), \
         patch('peer.client.check_peer_alive', return_value=True), \
         patch('builtins.print') as mock_print:
        
        ip, port = select_peer(mock_peers)
        assert ip is None
        assert port is None
        mock_print.assert_called_with("[!] Invalid selection")

def test_peer_client_menu_discovery(mock_peers):
    """Test peer discovery in menu"""
    with patch('builtins.input', side_effect=["5", "6"]), \
         patch('peer.client.discover_peers', return_value=mock_peers), \
         patch('builtins.print') as mock_print:
        
        peer_client_menu(mock_peers)
        mock_print.assert_any_call("[+] Found peers: [('127.0.0.1', 5050), ('192.168.1.2', 5051)]")

def test_peer_client_menu_exit():
    with patch('builtins.input', return_value="6"), \
         patch('builtins.print') as mock_print:
        peer_client_menu([])
        
        # Check if menu header was printed
        assert any("=== Peer Client Menu ===" in str(call) 
               for call in mock_print.call_args_list)