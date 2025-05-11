import pytest
from unittest.mock import patch, MagicMock
from peer.file_ops import list_shared_files, send_encrypted_file, receive_encrypted_file
import os
from config import SHARED_DIR, RECEIVED_DIR

@pytest.fixture
def setup_dirs(tmp_path, monkeypatch):
    """Setup shared and received directories with proper mocking"""
    shared = tmp_path / "shared"
    received = tmp_path / "received"
    shared.mkdir()
    received.mkdir()
    
    # Monkeypatch the config values at runtime
    monkeypatch.setattr('peer.file_ops.SHARED_DIR', str(shared))
    monkeypatch.setattr('peer.file_ops.RECEIVED_DIR', str(received))
    
    return {
        'shared_dir': shared,
        'received_dir': received
    }

def test_list_shared_files(setup_dirs):
    """Test listing files in shared directory"""
    # Create test files
    (setup_dirs['shared_dir'] / "file1.txt").write_text("test")
    (setup_dirs['shared_dir'] / "file2.txt").write_text("test")
    
    files = list_shared_files()
    assert len(files) == 2
    assert "file1.txt" in files
    assert "file2.txt" in files

def test_send_encrypted_file_success(setup_dirs):
    """Test successful file sending"""
    test_file = setup_dirs['shared_dir'] / "test.txt"
    test_file.write_text("test content")
    
    mock_conn = MagicMock()
    
    # Mock encrypted data and its length
    mock_data = b'encrypted_data'  # 13 bytes
    with patch('peer.file_ops.encrypt', return_value=mock_data):
        with patch('peer.file_ops.key', new=b'test_key'):
            result = send_encrypted_file(mock_conn, "test.txt")
    
    assert result is True
    # Verify the correct length header was sent (13 bytes)
    mock_conn.sendall.assert_any_call(f"{len(mock_data)}\n".encode())
    mock_conn.sendall.assert_any_call(mock_data)

def test_send_encrypted_file_failure(setup_dirs):
    """Test failed file sending"""
    mock_conn = MagicMock()
    
    # File doesn't exist
    result = send_encrypted_file(mock_conn, "nonexistent.txt")
    assert result is False

def test_receive_encrypted_file(setup_dirs):
    """Test file receiving"""
    mock_conn = MagicMock()
    mock_conn.recv.side_effect = [
        b"10", b"\n",  # Header
        b"encrypted10"  # Data
    ]
    
    with patch('peer.file_ops.decrypt', return_value=b"plaintext"):
        with patch('peer.file_ops.key', new=b'test_key'):
            receive_encrypted_file(mock_conn, "received.txt")
    
    # Verify file was created
    received_file = setup_dirs['received_dir'] / "received.txt"
    assert received_file.exists()
    assert received_file.read_text() == "plaintext"

   