"""Production-ready UniFi Controller/OS client with v1 API support."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Mapping
from uuid import UUID

import requests

from config import SUPPORTED_CONTROLLER_TYPES, UniFiConfig
from exceptions import (
    AuthenticationError,
    ConfigError,
    ControllerDetectionError,
    RequestContext,
    RequestError,
    ResponseParsingError,
)
from utils import (
    build_query_params,
    coerce_identifier,
    generate_totp_token,
    normalize_slug,
    parse_request_context,
    parse_response_data,
    parse_retry_after_seconds,
)


class UniFiClient:
    """UniFi API client supporting legacy, UniFi OS, and v1 endpoints."""

    TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        verify_ssl: bool = True,
        timeout: int = 10,
        *,
        username: str | None = None,
        password: str | None = None,
        mfa_secret: str | None = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        controller_type: str | None = None,
        config: UniFiConfig | None = None,
        session: requests.Session | None = None,
        sleep_func: Callable[[float], None] = time.sleep,
    ) -> None:
        if config is None:
            if base_url is None:
                raise ConfigError("base_url is required when config is not provided")
            config = UniFiConfig(
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

        self.config = config
        self.session = session if session is not None else requests.Session()
        self._sleep = sleep_func
        self._logger = logging.getLogger(__name__)

        self.session.verify = self.config.verify_ssl
        self.session.headers.update({"Accept": "application/json"})
        if self.config.api_key:
            self.session.headers["Authorization"] = f"Bearer {self.config.api_key}"

        self.controller_type: str | None = self.config.controller_type
        self.api_prefix = ""
        self._login_path: str | None = None
        self._logout_path: str | None = None
        self._authenticated = False

        if self.controller_type:
            self._set_controller_paths(self.controller_type)

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        session: requests.Session | None = None,
        sleep_func: Callable[[float], None] = time.sleep,
    ) -> "UniFiClient":
        """Build client from environment variables."""
        return cls(config=UniFiConfig.from_env(env), session=session, sleep_func=sleep_func)

    def __enter__(self) -> "UniFiClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        self.session.close()

    @staticmethod
    def to_slug(value: str) -> str:
        """Public slug normalization helper."""
        return normalize_slug(value)

    def _set_controller_paths(self, controller_type: str) -> None:
        if controller_type not in SUPPORTED_CONTROLLER_TYPES:
            raise ControllerDetectionError(
                "Unsupported controller_type. Expected one of: legacy, unifi_os."
            )

        self.controller_type = controller_type
        if controller_type == "unifi_os":
            self.api_prefix = "/proxy/network"
            self._login_path = "/api/auth/login"
            self._logout_path = "/api/auth/logout"
        else:
            self.api_prefix = ""
            self._login_path = "/api/login"
            self._logout_path = "/logout"

    def _ensure_controller_type(self) -> None:
        if self.controller_type:
            return

        if self.config.base_url_includes_proxy:
            self._set_controller_paths("unifi_os")
            return

        if self.config.uses_api_key:
            self._detect_controller_with_v1_probe()
            return

        self._detect_controller_with_login_probe()

    def _detect_controller_with_v1_probe(self) -> None:
        for candidate_type in ("unifi_os", "legacy"):
            prefix = "/proxy/network" if candidate_type == "unifi_os" else ""
            if self._probe_v1_sites(prefix):
                self._set_controller_paths(candidate_type)
                return

        raise ControllerDetectionError(
            "Unable to auto-detect controller type via v1 probes for API key authentication."
        )

    def _detect_controller_with_login_probe(self) -> None:
        probes = (
            ("unifi_os", "/api/auth/login"),
            ("legacy", "/api/login"),
        )
        for candidate_type, login_path in probes:
            if self._probe_endpoint_exists(login_path):
                self._set_controller_paths(candidate_type)
                return

        raise ControllerDetectionError(
            "Unable to auto-detect controller type via login endpoint probes."
        )

    def _probe_v1_sites(self, api_prefix: str) -> bool:
        url = f"{self.config.base_url}{api_prefix}/v1/sites"
        response: requests.Response | None = None
        try:
            response = self.session.get(url, timeout=self.config.timeout)
        except requests.RequestException as exc:
            self._logger.debug("Probe failed for %s: %s", url, exc)
            return False
        return response.status_code != 404

    def _probe_endpoint_exists(self, path: str) -> bool:
        url = self._build_url(path, api=False)
        methods = ("OPTIONS", "GET")
        for method in methods:
            try:
                response = self.session.request(method, url, timeout=self.config.timeout)
            except requests.RequestException as exc:
                self._logger.debug("Probe %s %s failed: %s", method, url, exc)
                continue
            if response.status_code != 404:
                return True
        return False

    def _authenticate(self, force: bool = False) -> None:
        self._ensure_controller_type()

        if self.config.uses_api_key:
            self.session.headers["Authorization"] = f"Bearer {self.config.api_key}"
            self._authenticated = True
            return

        if force:
            self._authenticated = False

        if self._authenticated:
            return

        self.login()

    def login(self) -> Any:
        """Authenticate using session login when username/password are configured."""
        self._ensure_controller_type()

        if self.config.uses_api_key:
            self._authenticate(force=True)
            return {"authenticated": True, "mode": "api_key"}

        if self._login_path is None:
            raise AuthenticationError("login path is not configured")

        payload: dict[str, Any] = {
            "username": self.config.username,
            "password": self.config.password,
        }

        if self.config.mfa_secret:
            try:
                payload["token"] = generate_totp_token(self.config.mfa_secret)
            except ValueError as exc:
                raise AuthenticationError("Invalid mfa_secret format") from exc

        try:
            response = self.request(
                "POST",
                self._login_path,
                api=False,
                require_auth=False,
                allow_reauth=False,
                allow_retry=False,
                json_body=payload,
            )
        except RequestError as exc:
            raise AuthenticationError("Login failed") from exc

        self._authenticated = True
        try:
            return parse_response_data(response)
        except ResponseParsingError:
            return {"authenticated": True, "mode": "session"}

    def logout(self) -> None:
        """Log out and clear local authentication state."""
        self._ensure_controller_type()

        if self.config.uses_api_key:
            self.session.headers.pop("Authorization", None)
            self._authenticated = False
            return

        if self._logout_path:
            self.request(
                "POST",
                self._logout_path,
                api=False,
                require_auth=False,
                allow_reauth=False,
                allow_retry=False,
            )

        self.session.cookies.clear()
        self._authenticated = False

    def _build_url(self, path: str, *, api: bool) -> str:
        if path.startswith(("http://", "https://")):
            return path

        normalized_path = path if path.startswith("/") else f"/{path}"
        if api and normalized_path.startswith("/v1/"):
            normalized_path = f"{self.api_prefix}{normalized_path}"
        return f"{self.config.base_url}{normalized_path}"

    def _retry_delay(self, attempt: int, response: requests.Response | None) -> float:
        delay = self.config.backoff_factor * (2**attempt)
        if response is not None and response.status_code == 429:
            retry_after = parse_retry_after_seconds(response.headers.get("Retry-After"))
            if retry_after is not None:
                delay = max(delay, retry_after)
        return delay

    def _log_request_context(self, context: RequestContext, *, level: int = logging.ERROR) -> None:
        self._logger.log(
            level,
            (
                "UniFi API error statusCode=%s statusName=%s code=%s message=%s "
                "requestId=%s method=%s url=%s"
            ),
            context.status_code,
            context.status_name,
            context.code,
            context.message,
            context.request_id,
            context.method,
            context.url,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        api: bool = True,
        params: Mapping[str, Any] | None = None,
        json_body: Any | None = None,
        require_auth: bool = True,
        allow_reauth: bool = True,
        allow_retry: bool = True,
    ) -> requests.Response:
        """Central request method with retries, backoff, and 401 re-auth."""
        self._ensure_controller_type()
        if require_auth:
            self._authenticate()

        url = self._build_url(path, api=api)
        max_attempts = self.config.max_retries + 1 if allow_retry else 1
        attempt = 0
        reauth_attempted = False

        while attempt < max_attempts:
            response: requests.Response | None = None
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_body,
                    timeout=self.config.timeout,
                )

                if (
                    response.status_code == 401
                    and allow_reauth
                    and require_auth
                    and not reauth_attempted
                ):
                    reauth_attempted = True
                    self._authenticate(force=True)
                    continue

                if (
                    response.status_code in self.TRANSIENT_STATUS_CODES
                    and attempt < max_attempts - 1
                ):
                    context = parse_request_context(response, method, url)
                    self._log_request_context(context, level=logging.WARNING)
                    delay = self._retry_delay(attempt, response)
                    if delay > 0:
                        self._sleep(delay)
                    attempt += 1
                    continue

                response.raise_for_status()
                return response
            except requests.HTTPError as exc:
                context = parse_request_context(response, method, url)
                self._log_request_context(context, level=logging.ERROR)
                if (
                    context.status_code == 401
                    and allow_reauth
                    and require_auth
                    and not reauth_attempted
                ):
                    reauth_attempted = True
                    self._authenticate(force=True)
                    continue
                raise RequestError(
                    f"UniFi request failed: {method.upper()} {url}",
                    context=context,
                ) from exc
            except requests.RequestException as exc:
                if attempt < max_attempts - 1:
                    delay = self._retry_delay(attempt, None)
                    self._logger.warning(
                        "Transient transport error for %s %s: %s (retry in %.2fs)",
                        method.upper(),
                        url,
                        exc,
                        delay,
                    )
                    if delay > 0:
                        self._sleep(delay)
                    attempt += 1
                    continue

                context = RequestContext(
                    message=str(exc),
                    method=method.upper(),
                    url=url,
                )
                raise RequestError(
                    f"UniFi transport error: {method.upper()} {url}",
                    context=context,
                ) from exc

        raise RequestError(
            f"UniFi retry budget exhausted: {method.upper()} {url}",
            context=RequestContext(method=method.upper(), url=url),
        )

    def _request_data(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any | None = None,
    ) -> Any:
        response = self.request(
            method=method,
            path=path,
            api=True,
            params=params,
            json_body=json_body,
        )
        return parse_response_data(response)

    def _get_collection(
        self,
        path: str,
        *,
        offset: int = 0,
        limit: int = 100,
        filters: Mapping[str, Any] | None = None,
        paginate: bool = False,
    ) -> Any:
        if not paginate:
            params = build_query_params(offset=offset, limit=limit, filters=filters)
            return self._request_data("GET", path, params=params)

        combined: list[Any] = []
        current_offset = offset
        while True:
            params = build_query_params(offset=current_offset, limit=limit, filters=filters)
            page = self._request_data("GET", path, params=params)
            if not isinstance(page, list):
                return page if not combined else combined

            combined.extend(page)
            if len(page) < limit:
                return combined
            current_offset += limit

    def get_sites(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        filters: Mapping[str, Any] | None = None,
        paginate: bool = False,
    ) -> Any:
        return self._get_collection(
            "/v1/sites",
            offset=offset,
            limit=limit,
            filters=filters,
            paginate=paginate,
        )

    def get_devices(
        self,
        site_id: str | UUID,
        *,
        offset: int = 0,
        limit: int = 100,
        filters: Mapping[str, Any] | None = None,
        paginate: bool = False,
    ) -> Any:
        site = coerce_identifier(site_id)
        return self._get_collection(
            f"/v1/sites/{site}/devices",
            offset=offset,
            limit=limit,
            filters=filters,
            paginate=paginate,
        )

    def get_clients(
        self,
        site_id: str | UUID,
        *,
        offset: int = 0,
        limit: int = 100,
        filters: Mapping[str, Any] | None = None,
        paginate: bool = False,
    ) -> Any:
        site = coerce_identifier(site_id)
        return self._get_collection(
            f"/v1/sites/{site}/clients",
            offset=offset,
            limit=limit,
            filters=filters,
            paginate=paginate,
        )

    def get_networks(
        self,
        site_id: str | UUID,
        *,
        offset: int = 0,
        limit: int = 100,
        filters: Mapping[str, Any] | None = None,
        paginate: bool = False,
    ) -> Any:
        site = coerce_identifier(site_id)
        return self._get_collection(
            f"/v1/sites/{site}/networks",
            offset=offset,
            limit=limit,
            filters=filters,
            paginate=paginate,
        )

    def get_device_details(self, site_id: str | UUID, device_id: str | UUID) -> Any:
        site = coerce_identifier(site_id)
        device = coerce_identifier(device_id)
        return self._request_data("GET", f"/v1/sites/{site}/devices/{device}")
