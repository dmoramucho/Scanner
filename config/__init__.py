"""Startup configuration — read once, validated, fail-fast.

Not part of the domain: this is the composition root's view of the environment. The
domain never reads config; it receives already-constructed ports.
"""

from config.settings import AppConfig, ConfigError, load_config

__all__ = ["AppConfig", "ConfigError", "load_config"]
