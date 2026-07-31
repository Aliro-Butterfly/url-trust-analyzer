from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

# Lazily initialised — computed once from the environment secret and cached for
# the lifetime of the process. Avoids re-hashing on every encrypt/decrypt call.
_fernet_instance: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        secret = os.getenv("API_KEYS_SECRET") or os.getenv("JWT_SECRET")
        if not secret:
            raise RuntimeError(
                "API_KEYS_SECRET or JWT_SECRET environment variable is required "
                "to encrypt stored API keys."
            )
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
        _fernet_instance = Fernet(key)
    return _fernet_instance


def encrypt_api_key(value: str) -> str:
    return _get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_api_key(token: str) -> str | None:
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None