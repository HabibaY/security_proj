import pytest
import os
from peer.auth import register_user, authenticate_user, hash_password, verify_password
from config import USER_DATA_FILE
import shutil

@pytest.fixture
def clean_auth_env(tmp_path, monkeypatch):
    """Fixture that provides a clean test environment"""
    # Setup paths
    test_dir = tmp_path / "auth_test"
    test_dir.mkdir()
    users_file = test_dir / "users.json"
    
    # Monkeypatch the config values used by auth.py
    monkeypatch.setattr('config.USER_DATA_FILE', str(users_file))
    
    # Also patch the derived paths in auth.py
    monkeypatch.setattr('peer.auth.SALT_FILE', str(users_file) + ".salt")
    monkeypatch.setattr('peer.auth.ENC_FILE', str(users_file) + ".enc")
    
    yield {
        "users_file": users_file,
        "enc_file": test_dir / "users.json.enc",
        "salt_file": test_dir / "users.json.salt"
    }
    
    # Cleanup
    try:
        shutil.rmtree(test_dir)
    except:
        pass

def test_user_registration(clean_auth_env):
    """Test successful user registration"""
    master_password = "testmaster123"
    
    # First registration should succeed
    success, message = register_user("admin", master_password)
    
    assert success is True, f"Initial registration failed: {message}"
    assert "successful" in message.lower()
    assert clean_auth_env["enc_file"].exists()
    assert clean_auth_env["salt_file"].exists()

def test_duplicate_registration(clean_auth_env):
    """Test duplicate user registration"""
    master_password = "testmaster123"
    
    # First registration (admin user)
    success, message = register_user("admin", master_password)
    assert success is True, f"Initial admin registration failed: {message}"
    
    # Test normal registration (different username)
    success, message = register_user("testuser", master_password)
    assert success is True, f"Normal registration failed: {message}"
    
    # Test duplicate username
    success, message = register_user("testuser", master_password)
    assert success is False
    assert "already exists" in message.lower()


def test_authentication_success(clean_auth_env):
    """Test successful authentication"""
    master_password = "testmaster123"
    
    # Register admin first
    register_user("admin", master_password)
    
    # Register test user
    register_user("testuser", master_password)
    
    # Test authentication
    assert authenticate_user("testuser", master_password) is True

def test_authentication_failure(clean_auth_env):
    """Test failed authentication"""
    master_password = "testmaster123"
    
    # Register admin first
    register_user("admin", master_password)
    
    # Register test user
    register_user("testuser", master_password)
    
    # Test wrong password
    assert authenticate_user("testuser", "wrongpassword") is False
    
    # Test non-existent user
    assert authenticate_user("nonexistent", master_password) is False

def test_password_hashing():
    """Test password hashing and verification"""
    password = "testpassword123"
    hashed = hash_password(password)
    assert verify_password(hashed, password) is True
    assert verify_password(hashed, "wrongpassword") is False

    