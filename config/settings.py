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
#:
#: The NVD settings live here because every one of them has a defensible default — the
#: public endpoint, and the rate limit NVD documents for *unauthenticated* callers, which is
#: the conservative choice. An operator with an API key raises the limit deliberately
#: (m3-design §2: respect the rate limit; never hammer NVD).
OPTIONAL_DEFAULTS: Final[Mapping[str, str]] = {
    "SCANNER_REGION": "us-east-1",
    "SCANNER_LOG_LEVEL": "INFO",
    "SCANNER_NVD_BASE_URL": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    # NVD documents 5 requests / 30 s without an API key, 50 with one. Defaulting to the
    # unauthenticated limit means a missing key costs throughput, never a rate-limit ban.
    "SCANNER_NVD_RATE_LIMIT_REQUESTS": "5",
    "SCANNER_NVD_RATE_LIMIT_WINDOW_SECONDS": "30",
    "SCANNER_NVD_TIMEOUT_SECONDS": "30",
    "SCANNER_NVD_MAX_RETRIES": "3",
    # A CVE record changes rarely; re-asking NVD for the same CPE inside a day is rude and
    # slow. Long enough to be kind to the feed, short enough that a new CVE lands the next
    # working day.
    "SCANNER_NVD_CACHE_TTL_HOURS": "24",
}


@dataclass(frozen=True, slots=True)
class NvdSettings:
    """How we talk to NVD: where, how fast, and how long we trust what it told us.

    Every field is configuration rather than a constant because NVD's limits differ with
    and without an API key, and an operator behind a slow link needs a longer timeout than
    a default we invented (m3-design §2).
    """

    base_url: str
    #: Optional: NVD works without one, ten times slower. A `Secret` because it is a
    #: credential, even a low-value one (AGENTS.md §2.10).
    api_key: Secret | None
    rate_limit_requests: int
    rate_limit_window_seconds: float
    timeout_seconds: float
    max_retries: int
    cache_ttl_hours: float

    @property
    def min_request_interval_seconds(self) -> float:
        """The gap the adapter keeps between requests to stay inside the cap."""
        return self.rate_limit_window_seconds / self.rate_limit_requests


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
    nvd: NvdSettings


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

    def positive_number(key: str) -> float:
        """A number an operator can get wrong in exactly two ways: unparseable, or zero."""
        raw = optional(key)
        try:
            value = float(raw)
        except ValueError as exc:
            raise ConfigError(f"{key} must be a number; got {raw!r}") from exc
        if value <= 0:
            raise ConfigError(f"{key} must be greater than zero; got {value}")
        return value

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
        nvd=NvdSettings(
            base_url=optional("SCANNER_NVD_BASE_URL"),
            api_key=(
                Secret(source["SCANNER_NVD_API_KEY"].strip())
                if source.get("SCANNER_NVD_API_KEY", "").strip()
                else None
            ),
            rate_limit_requests=int(positive_number("SCANNER_NVD_RATE_LIMIT_REQUESTS")),
            rate_limit_window_seconds=positive_number("SCANNER_NVD_RATE_LIMIT_WINDOW_SECONDS"),
            timeout_seconds=positive_number("SCANNER_NVD_TIMEOUT_SECONDS"),
            max_retries=int(positive_number("SCANNER_NVD_MAX_RETRIES")),
            cache_ttl_hours=positive_number("SCANNER_NVD_CACHE_TTL_HOURS"),
        ),
    )
