from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


API_KEYS_SECRET_KEY = os.getenv("API_KEYS_SECRET") or os.getenv("JWT_SECRET")

if not API_KEYS_SECRET_KEY:
    raise RuntimeError(
        "API_KEYS_SECRET or JWT_SECRET must be set in environment "
        "to ensure API key encryption is stable across restarts."
    )


def _api_keys_secret_key() -> bytes:
    secret = API_KEYS_SECRET_KEY.encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


def encrypt_api_key(value: str) -> str:
    return Fernet(_api_keys_secret_key()).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_api_key(token: str) -> str | None:
    try:
        return Fernet(_api_keys_secret_key()).decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None
