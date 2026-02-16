"""Utility helpers for UniFi client configuration and response handling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time
import unicodedata
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import requests

from exceptions import RequestContext, ResponseParsingError

_PROXY_NETWORK_SUFFIX = "/proxy/network"


def normalize_controller_url(base_url: str) -> tuple[str, bool]:
    """Normalize URL and strip trailing /proxy/network if present."""
    if not base_url or not base_url.strip():
        raise ValueError("base_url is required")

    parsed = urlsplit(base_url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("base_url must start with http:// or https://")
    if not parsed.netloc:
        raise ValueError("base_url must include a hostname")

    path = parsed.path.rstrip("/")
    includes_proxy_network = path.endswith(_PROXY_NETWORK_SUFFIX)
    if includes_proxy_network:
        path = path[: -len(_PROXY_NETWORK_SUFFIX)]

    normalized = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    return normalized.rstrip("/"), includes_proxy_network


def normalize_slug(value: str) -> str:
    """Lowercase slug with spaces replaced and special chars removed."""
    if not value or not value.strip():
        raise ValueError("slug input cannot be empty")

    ascii_value = (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    )
    lowered = ascii_value.lower()
    with_hyphens = re.sub(r"\s+", "-", lowered)
    cleaned = re.sub(r"[^a-z0-9-]", "", with_hyphens)
    compact = re.sub(r"-{2,}", "-", cleaned).strip("-")
    if not compact:
        raise ValueError("slug result is empty after normalization")
    return compact


def coerce_identifier(value: str | UUID) -> str:
    """Return UUID/identifier as non-empty string."""
    identifier = str(value).strip()
    if not identifier:
        raise ValueError("identifier is required")
    return identifier


def parse_bool(value: str | bool | None, default: bool) -> bool:
    """Parse booleans from env-style strings."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


def parse_int(value: str | None, default: int, field_name: str) -> int:
    """Parse int values with field-specific error context."""
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    return parsed


def parse_float(value: str | None, default: float, field_name: str) -> float:
    """Parse float values with field-specific error context."""
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a number") from exc
    return parsed


def build_query_params(
    offset: int = 0,
    limit: int = 100,
    filters: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build list query parameters, including optional filters."""
    if offset < 0:
        raise ValueError("offset must be >= 0")
    if limit <= 0:
        raise ValueError("limit must be > 0")

    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if not filters:
        return params

    for key, value in filters.items():
        if value is None:
            continue
        params[str(key)] = str(value) if isinstance(value, UUID) else value
    return params


def parse_retry_after_seconds(header_value: str | None) -> float | None:
    """Parse Retry-After header as seconds."""
    if not header_value:
        return None

    stripped = header_value.strip()
    if not stripped:
        return None

    try:
        return max(0.0, float(stripped))
    except ValueError:
        pass

    try:
        retry_dt = parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        return None

    if retry_dt.tzinfo is None:
        retry_dt = retry_dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0.0, (retry_dt - now).total_seconds())


def safe_json(response: requests.Response | None) -> Any | None:
    """Safely parse JSON without throwing."""
    if response is None:
        return None
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def parse_response_data(response: requests.Response | None) -> Any:
    """Parse response payload and return payload['data'] when present."""
    if response is None:
        raise ResponseParsingError("response is None")

    if not response.content:
        raise ResponseParsingError("response payload is empty")

    try:
        payload = response.json()
    except ValueError as exc:
        raise ResponseParsingError("response body is not valid JSON") from exc

    if payload is None:
        raise ResponseParsingError("response JSON is null")
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def parse_request_context(
    response: requests.Response | None,
    method: str,
    url: str,
) -> RequestContext:
    """Extract structured UniFi API error fields for logging/exceptions."""
    payload = safe_json(response)
    if isinstance(payload, dict):
        meta = payload.get("meta")
        raw_status_code = payload.get("statusCode", response.status_code if response else None)
        status_name = payload.get("statusName")
        code = payload.get("code")
        message = payload.get("message") or payload.get("msg")
        request_id = payload.get("requestId")
        if request_id is None and isinstance(meta, dict):
            request_id = meta.get("requestId")

        if message is None and isinstance(meta, dict):
            message = meta.get("msg")
        if code is None and isinstance(meta, dict):
            code = meta.get("rc")

        status_code: int | None
        if isinstance(raw_status_code, int):
            status_code = raw_status_code
        elif isinstance(raw_status_code, str) and raw_status_code.isdigit():
            status_code = int(raw_status_code)
        else:
            status_code = response.status_code if response is not None else None

        return RequestContext(
            status_code=status_code,
            status_name=str(status_name) if status_name is not None else None,
            code=str(code) if code is not None else None,
            message=str(message) if message is not None else None,
            request_id=str(request_id) if request_id is not None else None,
            method=method.upper(),
            url=url,
        )

    status_code = response.status_code if response is not None else None
    message = response.text.strip() if response is not None and response.text else None
    return RequestContext(
        status_code=status_code,
        message=message,
        method=method.upper(),
        url=url,
    )


def generate_totp_token(secret: str, timestamp: int | None = None) -> str:
    """Generate RFC 6238 TOTP token using SHA-1 and 30s interval."""
    if not secret or not secret.strip():
        raise ValueError("mfa secret is required")

    normalized = secret.strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized + padding, casefold=True)

    unix_time = int(time.time() if timestamp is None else timestamp)
    timestep = unix_time // 30
    msg = struct.pack(">Q", timestep)
    digest = hmac.new(key, msg, hashlib.sha1).digest()

    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    token = truncated % 1_000_000
    return f"{token:06d}"
