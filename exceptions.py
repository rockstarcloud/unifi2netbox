"""Custom exceptions for the UniFi client."""

from __future__ import annotations

from dataclasses import dataclass


class UniFiClientError(Exception):
    """Base exception for all client errors."""


class ConfigError(UniFiClientError):
    """Raised when configuration values are missing or invalid."""


class ControllerDetectionError(UniFiClientError):
    """Raised when controller type auto-detection fails."""


class AuthenticationError(UniFiClientError):
    """Raised when login or re-authentication fails."""


class ResponseParsingError(UniFiClientError):
    """Raised when API responses cannot be parsed safely."""


@dataclass(frozen=True)
class RequestContext:
    """Structured error context from UniFi API responses."""

    status_code: int | None = None
    status_name: str | None = None
    code: str | None = None
    message: str | None = None
    request_id: str | None = None
    url: str | None = None
    method: str | None = None


class RequestError(UniFiClientError):
    """Raised when HTTP requests fail after retries."""

    def __init__(self, message: str, context: RequestContext | None = None) -> None:
        super().__init__(message)
        self.context = context
