"""Config must fail fast and never substitute a default for something security-critical
(AGENTS.md §6)."""

from __future__ import annotations

import pytest

from config import AppConfig, ConfigError, load_config
from config.settings import OPTIONAL_DEFAULTS, REQUIRED_KEYS
from domain.secret import Secret

COMPLETE_ENV = {
    "SCANNER_ENV": "dev",
    "SCANNER_DATABASE_URL": "postgresql://scanner:pw@localhost:5432/scanner",
    "SCANNER_RAW_STORE_ENDPOINT_URL": "http://localhost:9000",
    "SCANNER_RAW_STORE_BUCKET": "scanner-raw",
    "SCANNER_RAW_STORE_ACCESS_KEY_ID": "scanner-local",
    "SCANNER_RAW_STORE_SECRET_ACCESS_KEY": "s3-secret-value",
    "SCANNER_SECRETS_ENDPOINT_URL": "http://localhost:4566",
}


def test_loads_a_complete_environment() -> None:
    config = load_config(COMPLETE_ENV)
    assert isinstance(config, AppConfig)
    assert config.environment == "dev"
    assert config.raw_store_bucket == "scanner-raw"


@pytest.mark.parametrize("missing_key", REQUIRED_KEYS)
def test_fails_fast_when_a_required_key_is_absent(missing_key: str) -> None:
    env = {k: v for k, v in COMPLETE_ENV.items() if k != missing_key}
    with pytest.raises(ConfigError) as exc_info:
        load_config(env)
    assert missing_key in str(exc_info.value)


@pytest.mark.parametrize("missing_key", REQUIRED_KEYS)
def test_blank_value_counts_as_missing(missing_key: str) -> None:
    """An exported-but-empty variable is an operator mistake, not a request for a default."""
    env = {**COMPLETE_ENV, missing_key: "   "}
    with pytest.raises(ConfigError) as exc_info:
        load_config(env)
    assert missing_key in str(exc_info.value)


def test_reports_every_missing_key_at_once() -> None:
    with pytest.raises(ConfigError) as exc_info:
        load_config({})
    message = str(exc_info.value)
    for key in REQUIRED_KEYS:
        assert key in message


def test_rejects_an_unknown_environment() -> None:
    with pytest.raises(ConfigError, match="SCANNER_ENV"):
        load_config({**COMPLETE_ENV, "SCANNER_ENV": "production-ish"})


def test_rejects_an_unknown_log_level() -> None:
    with pytest.raises(ConfigError, match="SCANNER_LOG_LEVEL"):
        load_config({**COMPLETE_ENV, "SCANNER_LOG_LEVEL": "TRACE"})


def test_applies_documented_defaults_only_to_optional_keys() -> None:
    config = load_config(COMPLETE_ENV)
    assert config.region == OPTIONAL_DEFAULTS["SCANNER_REGION"]
    assert config.log_level == OPTIONAL_DEFAULTS["SCANNER_LOG_LEVEL"]


def test_optional_overrides_are_honoured() -> None:
    config = load_config(
        {**COMPLETE_ENV, "SCANNER_REGION": "eu-west-1", "SCANNER_LOG_LEVEL": "debug"}
    )
    assert config.region == "eu-west-1"
    assert config.log_level == "DEBUG"


def test_credentials_are_wrapped_in_secret() -> None:
    config = load_config(COMPLETE_ENV)
    assert isinstance(config.database_url, Secret)
    assert isinstance(config.raw_store_secret_access_key, Secret)
    assert config.database_url.reveal() == COMPLETE_ENV["SCANNER_DATABASE_URL"]


def test_config_repr_does_not_leak_credentials() -> None:
    rendered = repr(load_config(COMPLETE_ENV))
    assert "s3-secret-value" not in rendered
    assert COMPLETE_ENV["SCANNER_DATABASE_URL"] not in rendered
    assert "***redacted***" in rendered


def test_config_is_immutable() -> None:
    config = load_config(COMPLETE_ENV)
    with pytest.raises(AttributeError):
        config.environment = "prod"  # type: ignore[misc]
