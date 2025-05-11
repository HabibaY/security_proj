import os
import socket
import pytest
from unittest.mock import patch, mock_open, MagicMock
from peer.server import handle_incoming_peer, start_peer_server
from peer.auth import create_session_token
from peer.crypto_utils import encrypt

# Mock data
TEST_KEY = b'\x00' * 32  # 256-bit key for AES
TEST_TOKEN = "a" * 32
TEST_USER = "testuser"
TEST_PASS = "testpass"

@pytest.fixture
def mock_socket_conn():
    """Fixture for mocking socket connection"""
    mock_conn = MagicMock()
    mock_conn.recv.side_effect = [b"PING", b""]  # First call returns PING, second ends
    return mock_conn

@pytest.fixture
def mock_auth():
    with patch('peer.server.authenticate_user') as mock_auth, \
         patch('peer.server.create_session_token') as mock_token, \
         patch('peer.server.is_session_valid') as mock_valid, \
         patch('peer.server.renew_session') as mock_renew:
        mock_auth.return_value = True
        mock_token.return_value = TEST_TOKEN
        mock_valid.return_value = True
        yield mock_auth, mock_token, mock_valid, mock_renew

@pytest.fixture
def mock_crypto():
    with patch('peer.server.encrypt') as mock_encrypt, \
         patch('peer.server.decrypt') as mock_decrypt, \
         patch('peer.server.load_key') as mock_load_key:
        mock_load_key.return_value = TEST_KEY
        mock_encrypt.return_value = b'encrypted_content'  # 17 bytes
        mock_decrypt.return_value = b'decrypted_data'
        yield mock_encrypt, mock_decrypt, mock_load_key

def test_ping_handler(mock_socket_conn):
    """Test that PING command returns PONG"""
    handle_incoming_peer(mock_socket_conn, ('127.0.0.1', 12345))
    mock_socket_conn.sendall.assert_called_with(b"PONG")

def test_register_handler(mock_socket_conn, mock_auth):
    """Test user registration"""
    mock_conn = MagicMock()
    mock_conn.recv.return_value = b"REGISTER testuser testpass"
    with patch('peer.server.register_user') as mock_register:
        mock_register.return_value = (True, "User created")
        handle_incoming_peer(mock_conn, ('127.0.0.1', 12345))
        mock_conn.sendall.assert_called_with(b"OK: User created")

def test_login_handler(mock_socket_conn, mock_auth):
    """Test successful login"""
    mock_conn = MagicMock()
    mock_conn.recv.return_value = b"LOGIN testuser testpass"
    handle_incoming_peer(mock_conn, ('127.0.0.1', 12345))
    mock_conn.sendall.assert_called_with(f"OK: {TEST_TOKEN}".encode())

def test_list_files_handler(mock_socket_conn, mock_auth):
    """Test LIST_FILES command"""
    mock_conn = MagicMock()
    mock_conn.recv.return_value = f"{TEST_TOKEN} LIST_FILES".encode()
    with patch('peer.server.list_shared_files') as mock_list:
        mock_list.return_value = ["file1.txt", "file2.txt"]
        handle_incoming_peer(mock_conn, ('127.0.0.1', 12345))
        mock_conn.sendall.assert_called_with(b"file1.txt\nfile2.txt")

def test_download_handler(mock_socket_conn, mock_auth, mock_crypto):
    """Test file download"""
    mock_conn = MagicMock()
    mock_conn.recv.side_effect = [
        f"{TEST_TOKEN} DOWNLOAD test.txt".encode(),
        b"READY"
    ]
    
    # Mock file operations
    with patch('peer.server.os.path.exists') as mock_exists, \
         patch('peer.server.open', mock_open(read_data=b'file_content')), \
         patch('peer.server.encrypt', return_value=b'encrypted_content'):
        
        mock_exists.return_value = True
        
        handle_incoming_peer(mock_conn, ('127.0.0.1', 12345))
        
        # Verify the file transfer protocol (17 bytes for 'encrypted_content')
        mock_conn.sendall.assert_any_call(b"SIZE:17\n")
        mock_conn.sendall.assert_any_call(b'encrypted_content')

def test_upload_handler(mock_socket_conn, mock_auth, mock_crypto):
    """Test file upload"""
    mock_conn = MagicMock()
    mock_conn.recv.side_effect = [
        f"{TEST_TOKEN} UPLOAD test.txt".encode(),
        b"10\n",  # Correct size header format
        b'chunk1chunk2',
        b''
    ]
    
    # Mock file operations
    with patch('peer.server.open', mock_open()) as mocked_file, \
         patch('peer.server.os.path.join', return_value='shared_files/test.txt'):
        handle_incoming_peer(mock_conn, ('127.0.0.1', 12345))
        
        # Verify file was saved
        mocked_file.assert_called_with('shared_files/test.txt', 'wb')
        mock_conn.sendall.assert_called_with(b"OK: File uploaded successfully")

def test_invalid_command(mock_socket_conn):
    """Test unknown command handling"""
    mock_conn = MagicMock()
    mock_conn.recv.return_value = b"INVALID_COMMAND"
    handle_incoming_peer(mock_conn, ('127.0.0.1', 12345))
    mock_conn.sendall.assert_called_with(b"ERROR: Unknown command")

def test_server_start():
    """Test server startup (basic smoke test)"""
    with patch('peer.server.socket.socket') as mock_socket, \
         patch('peer.server.threading.Thread') as mock_thread:
        
        # Create mock socket instance that works as a context manager
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        
        # Create mock connection
        mock_conn = MagicMock()
        mock_addr = ('127.0.0.1', 12345)
        
        # Configure accept side effect
        mock_sock_instance.accept.side_effect = [
            (mock_conn, mock_addr),  # First call returns a connection
            KeyboardInterrupt()       # Second call raises interrupt
        ]
        
        # Run the server (will exit on KeyboardInterrupt)
        start_peer_server(5000)
        
        # Verify server setup
        mock_sock_instance.bind.assert_called_with(("0.0.0.0", 5000))
        mock_sock_instance.listen.assert_called()
        
        # Verify thread was created for the connection
        mock_thread.assert_called_once_with(
            target=handle_incoming_peer,
            args=(mock_conn, mock_addr),
            daemon=True
        )