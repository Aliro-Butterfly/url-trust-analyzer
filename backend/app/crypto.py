from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken


def _api_keys_secret_value() -> str:
    secret = os.getenv("API_KEYS_SECRET") or os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError(
            "API_KEYS_SECRET or JWT_SECRET environment variable is required "
            "to encrypt stored API keys."
        )
    return secret


def _api_keys_secret_key() -> bytes:
    secret = _api_keys_secret_value().encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


def encrypt_api_key(value: str) -> str:
    return Fernet(_api_keys_secret_key()).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_api_key(token: str) -> str | None:
    try:
        return Fernet(_api_keys_secret_key()).decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None
