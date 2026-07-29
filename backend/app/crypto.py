from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


def _api_keys_secret_key() -> bytes:
    secret = os.getenv("API_KEYS_SECRET") or os.getenv("JWT_SECRET") or "url-trust-analyzer-default-secret"
    if not isinstance(secret, bytes):
        secret = secret.encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


def encrypt_api_key(value: str) -> str:
    return Fernet(_api_keys_secret_key()).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_api_key(token: str) -> str | None:
    try:
        return Fernet(_api_keys_secret_key()).decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None
