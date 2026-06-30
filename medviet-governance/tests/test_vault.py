# tests/test_vault.py
import pytest
import os
import pandas as pd
import json
from src.encryption.vault import SimpleVault

@pytest.fixture
def temp_vault_key(tmp_path):
    key_path = tmp_path / ".vault_key"
    return str(key_path)

def test_kek_preservation(temp_vault_key):
    # 1. Create first vault, generates key
    vault1 = SimpleVault(master_key_path=temp_vault_key)
    kek1 = vault1.kek
    assert os.path.exists(temp_vault_key)

    # 2. Create second vault using the same key file, must load same kek
    vault2 = SimpleVault(master_key_path=temp_vault_key)
    kek2 = vault2.kek
    assert kek1 == kek2

def test_encryption_roundtrip(temp_vault_key):
    vault = SimpleVault(master_key_path=temp_vault_key)
    original = "Nguyen Van A - CCCD: 012345678901"
    
    # Encrypt
    payload = vault.encrypt_data(original)
    assert "encrypted_dek" in payload
    assert "ciphertext" in payload
    assert payload["algorithm"] == "AES-256-GCM"

    # Decrypt
    decrypted = vault.decrypt_data(payload)
    assert decrypted == original

def test_encrypt_column(temp_vault_key):
    vault = SimpleVault(master_key_path=temp_vault_key)
    df = pd.DataFrame({"secret_col": ["secret1", "secret2"]})

    # Encrypt column
    df_encrypted = vault.encrypt_column(df, "secret_col")
    
    # Verify values are JSON strings containing encrypted data
    for val in df_encrypted["secret_col"]:
        payload = json.loads(val)
        assert "encrypted_dek" in payload
        assert "ciphertext" in payload
        
        # Decrypt to check correctness
        decrypted = vault.decrypt_data(payload)
        assert decrypted in ["secret1", "secret2"]
