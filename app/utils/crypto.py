from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet

_KEY_ENV = "SECRETS_ENCRYPTION_KEY"
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    key = os.environ.get(_KEY_ENV, "")
    if not key:
        key = Fernet.generate_key().decode()
        os.environ[_KEY_ENV] = key
    if isinstance(key, str):
        key = key.encode()
    _fernet = Fernet(key)
    return _fernet


def encrypt_value(plaintext: str) -> str:
    f = _get_fernet()
    return base64.b64encode(f.encrypt(plaintext.encode())).decode()


def decrypt_value(ciphertext_b64: str) -> str:
    f = _get_fernet()
    return f.decrypt(base64.b64decode(ciphertext_b64)).decode()


def mask_value(value: str, visible: int = 4) -> str:
    if len(value) <= visible:
        return "****"
    return f"****{value[-visible:]}"
