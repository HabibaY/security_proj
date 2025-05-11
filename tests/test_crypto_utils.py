import pytest
from peer.crypto_utils import load_key, encrypt, decrypt, derive_key_from_password
import os
import shutil
from unittest.mock import patch

@pytest.fixture
def clean_key_env(tmp_path):
    """Fixture that provides a clean test environment for key loading"""
    # Setup paths
    test_dir = tmp_path / "key_test"
    test_dir.mkdir()
    key_file = test_dir / "test_key.bin"
    
    # Set environment variable
    os.environ["KEY_FILE"] = str(key_file)
    
    yield {
        "key_file": key_file,
    }
    
    # Cleanup
    try:
        shutil.rmtree(test_dir)
    except:
        pass
    finally:
        os.environ.pop("KEY_FILE", None)

def test_key_loading(clean_key_env):
    """Test key generation and loading"""
    # First call generates key
    with patch('peer.crypto_utils.KEY_FILE', clean_key_env["key_file"]):
        key1 = load_key()
        assert os.path.exists(clean_key_env["key_file"])
    
    # Second call loads same key
    with patch('peer.crypto_utils.KEY_FILE', clean_key_env["key_file"]):
        key2 = load_key()
        assert key1 == key2
        assert os.path.exists(clean_key_env["key_file"])

def test_encryption_decryption():
    """Test encryption and decryption roundtrip"""
    key = os.urandom(32)  # Test with random key
    plaintext = b"Test secret message"
    
    ciphertext = encrypt(plaintext, key)
    assert ciphertext != plaintext  # Should be encrypted
    
    decrypted = decrypt(ciphertext, key)
    assert decrypted == plaintext

def test_key_derivation():
    """Test key derivation from password"""
    password = "testpassword"
    salt = b"testsalt123456"
    
    key1 = derive_key_from_password(password, salt)
    key2 = derive_key_from_password(password, salt)
    key3 = derive_key_from_password(password, b"differentsalt")
    
    assert len(key1) == 32
    assert key1 == key2  # Same password+salt = same key
    assert key1 != key3  # Different salt = different key

    