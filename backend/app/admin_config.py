from __future__ import annotations

import json
import logging

from .config import ADMIN_CONFIG_PATH, ADMIN_PASSWORD, ADMIN_USERNAME

logger = logging.getLogger(__name__)

CONFIG_PATH = ADMIN_CONFIG_PATH

DEFAULT_PROVIDERS = {
    "VirusTotal": {
        "coefficient": 2.0,
        "dimensions": {"threat_intel": 85},
    },
    "Google Safe Browsing": {
        "coefficient": 1.8,
        "dimensions": {"threat_intel": 90},
    },
    "AbuseIPDB": {
        "coefficient": 1.8,
        "dimensions": {"threat_intel": 50, "reputation": 60},
    },
    "AlienVault OTX": {
        "coefficient": 1.6,
        "dimensions": {"threat_intel": 65, "reputation": 55},
    },
    "URLVoid": {
        "coefficient": 1.5,
        "dimensions": {"blacklists": 60, "threat_intel": 50, "reputation": 50},
    },
    "ScamAdviser": {
        "coefficient": 1.4,
        "dimensions": {"reputation": 55, "threat_intel": 40},
    },
    "Reputation Signals": {
        "coefficient": 1.4,
        "dimensions": {"reputation": 40, "malware": 35, "blacklists": 30},
    },
    "Sucuri": {
        "coefficient": 1.3,
        "dimensions": {"malware": 60, "blacklists": 55},
    },
    "Cisco Talos": {
        "coefficient": 1.1,
        "dimensions": {"threat_intel": 55},
    },
    "URLScan": {
        "coefficient": 1.3,
        "dimensions": {"threat_intel": 55, "infrastructure": 50},
    },
    "ICANN/RDAP": {
        "coefficient": 1.2,
        "dimensions": {"age": 80, "transparency": 70},
    },
    "DNS Infrastructure": {
        "coefficient": 1.2,
        "dimensions": {"infrastructure": 55},
    },
    "HackerTarget": {
        "coefficient": 1.0,
        "dimensions": {"infrastructure": 45},
    },
    "URL Properties": {
        "coefficient": 0.8,
        "dimensions": {"https": 40, "infrastructure": 30},
    },
    "Mozilla Observatory": {
        "coefficient": 1.0,
        "dimensions": {"https": 90},
    },
    "Certificate Transparency": {
        "coefficient": 1.0,
        "dimensions": {"infrastructure": 50, "transparency": 80},
    },
    "Privacy": {
        "coefficient": 1.0,
        "dimensions": {"privacy": 60},
    },
}

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
    "providers": dict(DEFAULT_PROVIDERS),
}

_config_cache: dict | None = None


def _validate_score(value: int | float, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a number.")
    if value < 0 or value > 100:
        raise ValueError(f"{field_name} must be between 0 and 100.")


def _validate_coefficient(value: int | float, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a number.")
    if value <= 0 or value > 10:
        raise ValueError(f"{field_name} must be greater than 0 and lower or equal to 10.")


def _validate_dimension_weights(dimension_weights: dict[str, int]) -> None:
    expected_keys = set(DEFAULT_CONFIG["dimension_weights"].keys())
    received_keys = set(dimension_weights.keys())
    if received_keys != expected_keys:
        missing = sorted(expected_keys - received_keys)
        extra = sorted(received_keys - expected_keys)
        errors = []
        if missing:
            errors.append(f"missing keys: {', '.join(missing)}")
        if extra:
            errors.append(f"unknown keys: {', '.join(extra)}")
        raise ValueError(f"Invalid dimension_weights schema ({'; '.join(errors)}).")

    for key, value in dimension_weights.items():
        _validate_score(value, f"dimension_weights.{key}")


def _validate_providers_config(providers: dict[str, dict]) -> None:
    expected_provider_names = set(DEFAULT_PROVIDERS.keys())
    received_provider_names = set(providers.keys())
    if received_provider_names != expected_provider_names:
        missing = sorted(expected_provider_names - received_provider_names)
        extra = sorted(received_provider_names - expected_provider_names)
        errors = []
        if missing:
            errors.append(f"missing providers: {', '.join(missing)}")
        if extra:
            errors.append(f"unknown providers: {', '.join(extra)}")
        raise ValueError(f"Invalid providers schema ({'; '.join(errors)}).")

    for provider_name, provider_config in providers.items():
        if not isinstance(provider_config, dict):
            raise ValueError(f"providers.{provider_name} must be an object.")
        if "coefficient" not in provider_config or "dimensions" not in provider_config:
            raise ValueError(f"providers.{provider_name} must contain coefficient and dimensions.")

        _validate_coefficient(provider_config["coefficient"], f"providers.{provider_name}.coefficient")

        dimensions = provider_config["dimensions"]
        if not isinstance(dimensions, dict):
            raise ValueError(f"providers.{provider_name}.dimensions must be an object.")

        expected_dimensions = set(DEFAULT_PROVIDERS[provider_name]["dimensions"].keys())
        received_dimensions = set(dimensions.keys())
        if received_dimensions != expected_dimensions:
            missing = sorted(expected_dimensions - received_dimensions)
            extra = sorted(received_dimensions - expected_dimensions)
            errors = []
            if missing:
                errors.append(f"missing dimensions: {', '.join(missing)}")
            if extra:
                errors.append(f"unknown dimensions: {', '.join(extra)}")
            raise ValueError(f"Invalid providers.{provider_name}.dimensions schema ({'; '.join(errors)}).")

        for dimension_name, score in dimensions.items():
            _validate_score(score, f"providers.{provider_name}.dimensions.{dimension_name}")


def _load_config_raw() -> dict:
    global _config_cache
    if _config_cache is not None:
        return _config_cache
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                data = json.load(f)
            merged = _migrate_if_needed(data)
            _config_cache = merged
            return merged
        except Exception as exc:
            logger.warning("Failed to load admin config: %s", exc)
    _config_cache = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULT_CONFIG.items()}
    return _config_cache


def _migrate_if_needed(data: dict) -> dict:
    cfg = {**DEFAULT_CONFIG}
    if "dimension_weights" in data and isinstance(data["dimension_weights"], dict):
        cfg["dimension_weights"] = {**cfg["dimension_weights"], **data["dimension_weights"]}
    if "providers" in data and isinstance(data["providers"], dict):
        for name, prov in DEFAULT_PROVIDERS.items():
            if name in data["providers"] and isinstance(data["providers"][name], dict):
                stored = data["providers"][name]
                merged_prov = {"coefficient": stored.get("coefficient", prov["coefficient"])}
                dims = stored.get("dimensions")
                if dims is not None and isinstance(dims, dict):
                    merged_prov["dimensions"] = dict(dims)
                else:
                    merged_prov["dimensions"] = dict(prov["dimensions"])
                cfg["providers"][name] = merged_prov
    elif "provider_coefficients" in data and isinstance(data["provider_coefficients"], dict):
        coeffs = data["provider_coefficients"]
        for name, prov in DEFAULT_PROVIDERS.items():
            cfg["providers"][name] = {
                "coefficient": coeffs.get(name, prov["coefficient"]),
                "dimensions": dict(prov["dimensions"]),
            }
    return cfg


def _invalidate_cache():
    global _config_cache
    _config_cache = None


def get_dimension_weights() -> dict[str, int]:
    return dict(_load_config_raw()["dimension_weights"])


def get_providers_config() -> dict[str, dict]:
    return {k: dict(v) for k, v in _load_config_raw()["providers"].items()}


def get_provider_coefficient(name: str) -> float:
    prov = _load_config_raw()["providers"].get(name)
    return prov["coefficient"] if prov else 1.0


def get_provider_dimensions(name: str) -> dict[str, int]:
    prov = _load_config_raw()["providers"].get(name)
    return dict(prov["dimensions"]) if prov else {}


def get_full_config() -> dict:
    return {
        "dimension_weights": get_dimension_weights(),
        "providers": get_providers_config(),
    }


def update_config(dimension_weights: dict[str, int] | None = None,
                  providers: dict[str, dict] | None = None) -> dict:
    current = _load_config_raw()
    if dimension_weights is not None:
        _validate_dimension_weights(dimension_weights)
        current["dimension_weights"] = dimension_weights
    if providers is not None:
        _validate_providers_config(providers)
        current["providers"] = providers
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
        _invalidate_cache()
    except Exception as exc:
        logger.error("Failed to write admin config: %s", exc)
        raise
    return get_full_config()

