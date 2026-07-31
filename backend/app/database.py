from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

_write_lock = threading.Lock()


def database_path() -> str:
    env_path = os.getenv("URL_TRUST_ANALYZER_DB")
    if env_path:
        return env_path

    root = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(root, "analysis_history.db")


def get_connection() -> sqlite3.Connection:
    path = database_path()
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL mode allows concurrent reads alongside one writer
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


from .crypto import decrypt_api_key, encrypt_api_key


def initialize_database() -> None:
    with _write_lock:
        with get_connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    url TEXT NOT NULL,
                    overall_score INTEGER NOT NULL,
                    confidence INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    provider TEXT NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, provider)
                )
                """
            )
            columns = [row[1] for row in connection.execute("PRAGMA table_info(history)").fetchall()]
            if "user_id" not in columns:
                connection.execute("ALTER TABLE history ADD COLUMN user_id INTEGER")
            connection.commit()


def save_analysis(report: dict[str, Any], username: str) -> None:
    with _write_lock:
        with get_connection() as connection:
            user_row = connection.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not user_row:
                return

            connection.execute(
                "INSERT INTO history (user_id, url, overall_score, confidence, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    user_row["id"],
                    report["url"],
                    report["overall_score"],
                    report["confidence"],
                    json.dumps(report, ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            connection.commit()


def create_user(username: str, password_hash: str) -> None:
    with _write_lock:
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            connection.commit()


def get_user_by_username(username: str) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None


def save_api_key(username: str, provider: str, api_key: str | None) -> None:
    user_row = get_user_by_username(username)
    if not user_row:
        return

    with _write_lock:
        with get_connection() as connection:
            if not api_key:
                connection.execute(
                    "DELETE FROM api_keys WHERE user_id = ? AND provider = ?",
                    (user_row["id"], provider),
                )
            else:
                encrypted_value = encrypt_api_key(api_key)
                connection.execute(
                    "INSERT INTO api_keys (user_id, provider, encrypted_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
                    " ON CONFLICT(user_id, provider) DO UPDATE SET encrypted_key = excluded.encrypted_key, updated_at = excluded.updated_at",
                    (
                        user_row["id"],
                        provider,
                        encrypted_value,
                        datetime.now(timezone.utc).isoformat(),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            connection.commit()


def fetch_api_keys(username: str) -> dict[str, str]:
    user_row = get_user_by_username(username)
    if not user_row:
        return {}

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT provider, encrypted_key FROM api_keys WHERE user_id = ?",
            (user_row["id"],),
        ).fetchall()

    api_keys: dict[str, str] = {}
    for row in rows:
        decrypted = decrypt_api_key(row["encrypted_key"])
        if decrypted is not None:
            api_keys[row["provider"]] = decrypted
    return api_keys


def fetch_history(limit: int = 20, username: str | None = None) -> list[dict[str, Any]]:
    with get_connection() as connection:
        if username:
            user_row = connection.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not user_row:
                return []
            rows = connection.execute(
                "SELECT id, url, overall_score, confidence, payload, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                (user_row["id"], limit),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT id, url, overall_score, confidence, payload, created_at FROM history ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        history: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload"])
            history.append(
                {
                    "id": row["id"],
                    "url": row["url"],
                    "overall_score": row["overall_score"],
                    "confidence": row["confidence"],
                    "created_at": row["created_at"],
                    "report": payload,
                }
            )
        return history