"""Startup configuration: validated once, fail-fast, no silent insecure defaults.

AGENTS.md §6: "Config separated from code; validate config at startup and fail fast on
missing critical config — never fall back to an insecure default silently."

Two deliberate choices:
  * An empty or whitespace-only value counts as *missing*. An exported-but-blank
    `SCANNER_DATABASE_URL` is an operator mistake, not an instruction to guess.
  * Every missing key is reported at once, so a misconfigured deployment is fixed in one
    pass rather than one restart per variable.

Secret-bearing values are wrapped in `domain.secret.Secret`, so a config object landing
in a log line or a traceback redacts them; `.reveal()` marks the few places they are
actually used (AGENTS.md §2.10).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from domain.secret import Secret


class ConfigError(Exception):
    """Startup configuration is missing or invalid. Always fatal — never recovered from
    by substituting a default."""


ENVIRONMENTS: Final = ("dev", "staging", "prod")
LOG_LEVELS: Final = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: No default is possible for these: each one either points at infrastructure we cannot
#: guess or carries a credential we must never invent.
REQUIRED_KEYS: Final = (
    "SCANNER_ENV",
    "SCANNER_DATABASE_URL",
    "SCANNER_RAW_STORE_ENDPOINT_URL",
    "SCANNER_RAW_STORE_BUCKET",
    "SCANNER_RAW_STORE_ACCESS_KEY_ID",
    "SCANNER_RAW_STORE_SECRET_ACCESS_KEY",
    "SCANNER_SECRETS_ENDPOINT_URL",
)

#: Safe to default: neither choice weakens security.
OPTIONAL_DEFAULTS: Final[Mapping[str, str]] = {
    "SCANNER_REGION": "us-east-1",
    "SCANNER_LOG_LEVEL": "INFO",
}


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Validated startup configuration. Immutable: re-reading the environment mid-run
    would make the fail-fast check meaningless."""

    environment: str
    database_url: Secret  # DSNs carry a password — treat the whole value as secret
    raw_store_endpoint_url: str  # MinIO / S3-compatible object store (raw records)
    raw_store_bucket: str
    raw_store_access_key_id: str
    raw_store_secret_access_key: Secret
    secrets_endpoint_url: str  # the in-perimeter vault behind SecretsPort
    region: str
    log_level: str


def load_config(env: Mapping[str, str] | None = None) -> AppConfig:
    """Read, validate, and freeze configuration. Raises `ConfigError` on anything missing
    or invalid — the process must not start half-configured.

    `env` defaults to `os.environ`; passing a mapping keeps this testable without
    mutating global state.
    """
    source: Mapping[str, str] = os.environ if env is None else env

    missing = [key for key in REQUIRED_KEYS if not source.get(key, "").strip()]
    if missing:
        raise ConfigError(
            "missing required configuration: "
            + ", ".join(missing)
            + " (set them in the environment or .env; see .env.example). "
            "No defaults are applied for these."
        )

    def optional(key: str) -> str:
        """Blank counts as unset — but only for keys with a safe documented default."""
        return source.get(key, "").strip() or OPTIONAL_DEFAULTS[key]

    environment = source["SCANNER_ENV"].strip()
    if environment not in ENVIRONMENTS:
        raise ConfigError(
            f"SCANNER_ENV must be one of {', '.join(ENVIRONMENTS)}; got {environment!r}"
        )

    log_level = optional("SCANNER_LOG_LEVEL").upper()
    if log_level not in LOG_LEVELS:
        raise ConfigError(
            f"SCANNER_LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}; got {log_level!r}"
        )

    return AppConfig(
        environment=environment,
        database_url=Secret(source["SCANNER_DATABASE_URL"].strip()),
        raw_store_endpoint_url=source["SCANNER_RAW_STORE_ENDPOINT_URL"].strip(),
        raw_store_bucket=source["SCANNER_RAW_STORE_BUCKET"].strip(),
        raw_store_access_key_id=source["SCANNER_RAW_STORE_ACCESS_KEY_ID"].strip(),
        raw_store_secret_access_key=Secret(source["SCANNER_RAW_STORE_SECRET_ACCESS_KEY"].strip()),
        secrets_endpoint_url=source["SCANNER_SECRETS_ENDPOINT_URL"].strip(),
        region=optional("SCANNER_REGION"),
        log_level=log_level,
    )
