from __future__ import annotations

import urllib.parse

import httpx


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def _user_agent() -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )


async def _fetch_text(url: str, timeout: float = 10.0) -> str | None:
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": _user_agent()},
            follow_redirects=True,
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except Exception:
        return None


def _extract_domain(url: str) -> str | None:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname or None
    except Exception:
        return None
