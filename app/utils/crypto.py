from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet

from app.config import settings

_KEY_ENV = "SECRETS_ENCRYPTION_KEY"
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    key = os.environ.get(_KEY_ENV, "") or settings.secrets_encryption_key
    if not key:
        key_file = settings.data_dir_path / "secrets.key"
        if key_file.exists():
            key = key_file.read_text(encoding="utf-8").strip()
        else:
            settings.data_dir_path.mkdir(parents=True, exist_ok=True)
            key = Fernet.generate_key().decode()
            key_file.write_text(key, encoding="utf-8")
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
