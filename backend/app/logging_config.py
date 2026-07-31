"""Structured logging configuration.

Sensitive fields (passwords, tokens, API keys, secrets) are never logged.
Import and call setup_logging() once at application startup.
"""
from __future__ import annotations

import logging
from pathlib import Path


_SENSITIVE_KEYWORDS = frozenset({
    "password", "password_hash", "jwt", "token", "cookie",
    "api_key", "secret", "authorization", "access_token",
    "refresh_token", "admin_token", "auth_token",
})


class _SanitizingFilter(logging.Filter):
    """Redact log records that mention sensitive field names."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = str(record.msg).lower()
        if any(k in msg for k in _SENSITIVE_KEYWORDS):
            record.msg = "[REDACTED — log message contained a sensitive field name]"
            record.args = ()
        return True


def setup_logging(log_file: Path | None = None, level: str = "WARNING") -> None:
    """Configure application-wide logging.

    Args:
        log_file: Optional path to a log file.  If None, logs to stderr only.
        level:    Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    numeric_level = getattr(logging, level.upper(), logging.WARNING)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    sanitizer = _SanitizingFilter()

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(str(log_file), mode="a", encoding="utf-8"))

    for handler in handlers:
        handler.setFormatter(fmt)
        handler.addFilter(sanitizer)

    logging.basicConfig(level=numeric_level, handlers=handlers, force=True)
    # Silence noisy third-party loggers in production
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)