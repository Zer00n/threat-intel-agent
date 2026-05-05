import os

from app.utils.crypto import decrypt_value, encrypt_value, mask_value


class TestEncryptDecrypt:
    def test_roundtrip(self):
        plaintext = "sk-ant-api03-test-key-value"
        encrypted = encrypt_value(plaintext)
        assert encrypted != plaintext
        decrypted = decrypt_value(encrypted)
        assert decrypted == plaintext

    def test_different_encryptions(self):
        val = "same-value"
        enc1 = encrypt_value(val)
        enc2 = encrypt_value(val)
        # Both decrypt to same value (but may differ due to IV)
        assert decrypt_value(enc1) == val
        assert decrypt_value(enc2) == val

    def test_empty_string(self):
        encrypted = encrypt_value("")
        assert decrypt_value(encrypted) == ""


class TestMaskValue:
    def test_long_value(self):
        assert mask_value("sk-ant-api03-1234") == "****1234"

    def test_short_value(self):
        assert mask_value("abc") == "****"

    def test_exact_length(self):
        assert mask_value("1234") == "****"
