"""Configuration model for the UniFi client."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping

from exceptions import ConfigError
from utils import normalize_controller_url, parse_bool, parse_float, parse_int

SUPPORTED_CONTROLLER_TYPES = {"legacy", "unifi_os"}


@dataclass(frozen=True)
class UniFiConfig:
    """Validated runtime configuration."""

    base_url: str
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    mfa_secret: str | None = None
    verify_ssl: bool = True
    timeout: int = 10
    max_retries: int = 3
    backoff_factor: float = 0.5
    controller_type: str | None = None
    base_url_includes_proxy: bool = field(init=False)

    def __post_init__(self) -> None:
        try:
            normalized_base_url, includes_proxy = normalize_controller_url(self.base_url)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc

        object.__setattr__(self, "base_url", normalized_base_url)
        object.__setattr__(self, "base_url_includes_proxy", includes_proxy)

        api_key = self.api_key.strip() if self.api_key and self.api_key.strip() else None
        username = self.username.strip() if self.username and self.username.strip() else None
        password = self.password.strip() if self.password and self.password.strip() else None
        mfa_secret = self.mfa_secret.strip() if self.mfa_secret and self.mfa_secret.strip() else None

        object.__setattr__(self, "api_key", api_key)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password)
        object.__setattr__(self, "mfa_secret", mfa_secret)

        if api_key is None and (username is None or password is None):
            raise ConfigError(
                "Either api_key or both username and password must be provided."
            )

        if self.timeout <= 0:
            raise ConfigError("timeout must be > 0")
        if self.max_retries < 0:
            raise ConfigError("max_retries must be >= 0")
        if self.backoff_factor < 0:
            raise ConfigError("backoff_factor must be >= 0")

        normalized_controller_type = (
            self.controller_type.strip().lower() if self.controller_type else None
        )
        if normalized_controller_type and normalized_controller_type not in SUPPORTED_CONTROLLER_TYPES:
            raise ConfigError(
                "controller_type must be one of: legacy, unifi_os"
            )
        object.__setattr__(self, "controller_type", normalized_controller_type)

    @property
    def uses_api_key(self) -> bool:
        return self.api_key is not None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "UniFiConfig":
        """Build and validate config from environment variables."""
        source = os.environ if env is None else env

        try:
            base_url = source["UNIFI_BASE_URL"]
        except KeyError as exc:
            raise ConfigError("Missing required environment variable: UNIFI_BASE_URL") from exc

        api_key = source.get("UNIFI_API_KEY")
        username = source.get("UNIFI_USERNAME")
        password = source.get("UNIFI_PASSWORD")
        mfa_secret = source.get("UNIFI_MFA_SECRET")
        controller_type = source.get("UNIFI_CONTROLLER_TYPE")

        try:
            verify_ssl = parse_bool(source.get("UNIFI_VERIFY_SSL"), default=True)
            timeout = parse_int(source.get("UNIFI_TIMEOUT"), default=10, field_name="UNIFI_TIMEOUT")
            max_retries = parse_int(
                source.get("UNIFI_MAX_RETRIES"),
                default=3,
                field_name="UNIFI_MAX_RETRIES",
            )
            backoff_factor = parse_float(
                source.get("UNIFI_BACKOFF_FACTOR"),
                default=0.5,
                field_name="UNIFI_BACKOFF_FACTOR",
            )
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc

        return cls(
            base_url=base_url,
            api_key=api_key,
            username=username,
            password=password,
            mfa_secret=mfa_secret,
            verify_ssl=verify_ssl,
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            controller_type=controller_type,
        )
