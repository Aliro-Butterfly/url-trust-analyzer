from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any


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
    return conn


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                overall_score INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


def save_analysis(report: dict[str, Any]) -> None:
    initialize_database()
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO history (url, overall_score, confidence, payload, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                report["url"],
                report["overall_score"],
                report["confidence"],
                json.dumps(report, ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()


def fetch_history(limit: int = 20) -> list[dict[str, Any]]:
    initialize_database()
    with get_connection() as connection:
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
