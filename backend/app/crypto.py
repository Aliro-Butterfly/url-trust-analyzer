from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


_API_KEYS_DEFAULT = "url-trust-analyzer-default-secret"

if os.getenv("API_KEYS_SECRET"):
    _API_KEYS_SECRET_KEY: str = os.getenv("API_KEYS_SECRET")  # type: ignore[assignment]
elif os.getenv("JWT_SECRET"):
    _API_KEYS_SECRET_KEY = os.getenv("JWT_SECRET")  # type: ignore[assignment]
else:
    _API_KEYS_SECRET_KEY = _API_KEYS_DEFAULT


def _api_keys_secret_key() -> bytes:
    secret = _API_KEYS_SECRET_KEY.encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


def encrypt_api_key(value: str) -> str:
    return Fernet(_api_keys_secret_key()).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_api_key(token: str) -> str | None:
    try:
        return Fernet(_api_keys_secret_key()).decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None
