from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = CONFIG_DIR / "admin_config.json"

DEFAULT_CONFIG = {
    "dimension_weights": {
        "malware": 27,
        "blacklists": 18,
        "threat_intel": 18,
        "reputation": 13,
        "infrastructure": 9,
        "privacy": 10,
        "age": 3,
        "transparency": 2,
        "https": 0,
    },
    "provider_coefficients": {
        "VirusTotal": 2.0,
        "Google Safe Browsing": 1.8,
        "AbuseIPDB": 1.8,
        "AlienVault OTX": 1.6,
        "URLVoid": 1.5,
        "ScamAdviser": 1.4,
        "Reputation Signals": 1.4,
        "Sucuri": 1.3,
        "URLScan": 1.3,
        "ICANN/RDAP": 1.2,
        "DNS Infrastructure": 1.2,
        "HackerTarget": 1.0,
        "URL Properties": 0.8,
        "Mozilla Observatory": 1.0,
        "Certificate Transparency": 1.0,
        "Privacy": 1.0,
    },
}

_config_cache: dict | None = None


def _load_config_raw() -> dict:
    global _config_cache
    if _config_cache is not None:
        return _config_cache
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                data = json.load(f)
            merged = {**DEFAULT_CONFIG}
            for key in ("dimension_weights", "provider_coefficients"):
                if key in data and isinstance(data[key], dict):
                    merged[key] = {**DEFAULT_CONFIG[key], **data[key]}
            _config_cache = merged
            return merged
        except Exception as exc:
            logger.warning("Failed to load admin config: %s", exc)
    _config_cache = dict(DEFAULT_CONFIG)
    return _config_cache


def _invalidate_cache():
    global _config_cache
    _config_cache = None


def get_dimension_weights() -> dict[str, int]:
    return dict(_load_config_raw()["dimension_weights"])


def get_provider_coefficients() -> dict[str, float]:
    return dict(_load_config_raw()["provider_coefficients"])


def get_full_config() -> dict:
    return {
        "dimension_weights": get_dimension_weights(),
        "provider_coefficients": get_provider_coefficients(),
    }


def update_config(dimension_weights: dict[str, int] | None = None,
                  provider_coefficients: dict[str, float] | None = None) -> dict:
    current = _load_config_raw()
    if dimension_weights is not None:
        current["dimension_weights"] = dimension_weights
    if provider_coefficients is not None:
        current["provider_coefficients"] = provider_coefficients
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
        _invalidate_cache()
    except Exception as exc:
        logger.error("Failed to write admin config: %s", exc)
        raise
    return get_full_config()


ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
