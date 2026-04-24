"""Read-mostly HTTP connection to Dependency-Track.

Supports two auth modes, selected automatically at construction time:

  1. API key  — if ``DTRACK_API_KEY`` is set, sent as ``X-Api-Key`` header.
  2. Login+password — ``DTRACK_USER`` + ``DTRACK_PASSWORD``, exchanged for a
     JWT via ``POST /api/v1/user/login``, then sent as ``Authorization:
     Bearer <jwt>``. JWT is re-fetched on 401.

Only whitelisted ``(method, path)`` pairs are allowed:

  * ``GET *`` — any path.
  * ``POST /api/v1/user/login`` — authentication, handled in ``_login``
    (bypasses the data-plane guard).
  * ``POST /api/v1/bom`` — CycloneDX SBOM upload (v0.2 ``upload_bom``).
  * ``PUT /api/v1/analysis`` — analyst triage writes (state, justification,
    comment). Dependency-Track v4 records analysis decisions via PUT,
    not POST; whitelisting POST here returned HTTP 405.

Any other method/path combination raises ``RuntimeError`` inside
``_guard`` before reaching the network. See ``feedback_dtrack_readonly.md``.
"""

from __future__ import annotations

import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
_RETRY_AFTER_CAP_SECONDS = 60.0


def _parse_minor(version: str) -> tuple[int, int]:
    """Extract (major, minor) from a DT version string. Returns (0, 0) on failure."""
    parts = version.split(".")
    try:
        major = int("".join(c for c in parts[0] if c.isdigit()) or "0")
        minor = int("".join(c for c in parts[1] if c.isdigit()) or "0") if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return (0, 0)
    return (major, minor)


class DTrackError(Exception):
    """Base error for Dependency-Track connection issues."""


class DTrackAuthError(DTrackError):
    """Authentication failed: bad credentials, expired token, 401, or 403."""


class DTrackHTTPError(DTrackError):
    """Dependency-Track returned a non-2xx response (other than 401/403)."""

    def __init__(self, status_code: int, message: str, path: str) -> None:
        super().__init__(f"HTTP {status_code} on {path}: {message}")
        self.status_code = status_code
        self.path = path


@dataclass
class DTrackConfig:
    base_url: str
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    verify_tls: bool = False
    timeout: float = 30.0
    retry_max: int = 3
    retry_backoff_ms: int = 500

    @classmethod
    def from_env(cls) -> "DTrackConfig":
        base_url = os.environ.get("DTRACK_URL")
        if not base_url:
            raise DTrackError("DTRACK_URL is not set")
        return cls(
            base_url=base_url.rstrip("/"),
            api_key=os.environ.get("DTRACK_API_KEY") or None,
            username=os.environ.get("DTRACK_USER") or None,
            password=os.environ.get("DTRACK_PASSWORD") or None,
            verify_tls=os.environ.get("DTRACK_VERIFY_TLS", "false").lower() == "true",
            timeout=float(os.environ.get("DTRACK_TIMEOUT", "30")),
            retry_max=int(os.environ.get("DTRACK_RETRY_MAX", "3")),
            retry_backoff_ms=int(os.environ.get("DTRACK_RETRY_BACKOFF_MS", "500")),
        )

    def has_api_key(self) -> bool:
        return bool(self.api_key)

    def has_login(self) -> bool:
        return bool(self.username and self.password)


class Connection:
    """Read-mostly HTTP connection to Dependency-Track.

    Use as a context manager::

        with Connection(DTrackConfig.from_env()) as dt:
            projects = dt.get("/api/v1/project", params={"pageSize": 50})

    Public methods:
      * ``get(path, params)``      — any path.
      * ``get_raw(path, params)``  — any path, binary response.
      * ``put_json(path, body)``   — only whitelisted data-plane paths.
      * ``post_json(path, body)``  — only whitelisted data-plane paths.

    Any other method/path combination is refused by ``_guard`` before
    reaching the network.
    """

    _LOGIN_PATH = "/api/v1/user/login"
    _WRITE_ALLOWED: dict[str, frozenset[str]] = {
        "PUT": frozenset({"/api/v1/analysis"}),
        "POST": frozenset({"/api/v1/bom"}),
    }

    def __init__(self, config: DTrackConfig) -> None:
        if not config.has_api_key() and not config.has_login():
            raise DTrackError(
                "no credentials: set DTRACK_API_KEY or DTRACK_USER+DTRACK_PASSWORD"
            )
        self._config = config
        self._jwt: str | None = None
        self._version_checked = False
        # trust_env=False disables HTTP(S)_PROXY/NO_PROXY from the
        # environment. Dependency-Track is on an internal host that the
        # corporate proxy refuses to tunnel — same reason curl needs
        # --noproxy '*'.
        self._client = httpx.Client(
            base_url=config.base_url,
            verify=config.verify_tls,
            timeout=config.timeout,
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API — the only methods tools are allowed to call.
    # ------------------------------------------------------------------

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET ``path`` and return parsed JSON (or ``None`` if body empty).

        Retries once after a fresh login on 401 when using JWT auth.
        """
        resp = self._request_with_auth_retry("GET", path, params=params)
        self._maybe_check_version()
        if not resp.content:
            return None
        return resp.json()

    def get_raw(
        self, path: str, params: dict[str, Any] | None = None
    ) -> tuple[bytes, str]:
        """GET ``path`` and return (body, content_type).

        Use for binary or large payloads (SBOM downloads, reports) where
        parsing JSON into memory is wasteful or wrong.
        """
        resp = self._request_with_auth_retry("GET", path, params=params)
        return resp.content, resp.headers.get("content-type", "")

    def put_json(self, path: str, body: dict[str, Any]) -> Any:
        """PUT ``body`` as JSON to ``path``.

        Only whitelisted paths are allowed (see ``_WRITE_ALLOWED``).
        Any other path raises ``RuntimeError`` in ``_guard`` before the
        request leaves the process. Retries once after a fresh login on
        401 when using JWT auth.
        """
        resp = self._request_with_auth_retry("PUT", path, json_body=body)
        if not resp.content:
            return None
        return resp.json()

    def post_json(self, path: str, body: dict[str, Any]) -> Any:
        """POST ``body`` as JSON to ``path``.

        Only whitelisted paths are allowed (see ``_WRITE_ALLOWED``). Used
        for SBOM uploads (``/api/v1/bom``) in v0.2; the login endpoint
        does NOT go through this method — it bypasses the guard via
        ``_login``. Retries once after a fresh login on 401.
        """
        resp = self._request_with_auth_retry("POST", path, json_body=body)
        if not resp.content:
            return None
        return resp.json()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _request_with_auth_retry(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        for attempt in (1, 2):
            headers = self._auth_headers()
            resp = self._send_with_retry(method, path, params, json_body, headers)
            if (
                resp.status_code == 401
                and self._config.has_login()
                and attempt == 1
            ):
                logger.info(
                    "dtrack: 401 on %s %s, refreshing JWT and retrying",
                    method,
                    path,
                )
                self._jwt = None
                continue
            self._raise_for_status(resp, path)
            return resp
        raise DTrackAuthError(f"authentication failed for {method} {path}")

    def _send_with_retry(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        json_body: dict[str, Any] | None,
        headers: dict[str, str],
    ) -> httpx.Response:
        """Wrap ``_send`` with rate-limit / transient-failure retries.

        Retries on HTTP 429, 502, 503, 504 and on transport-level errors
        (connection refused, read timeout). Exponential backoff with
        jitter; ``Retry-After`` header honoured up to a 60 s cap. Does
        not retry on 401 (handled by ``_request_with_auth_retry``), on
        other 4xx, or on guard refusals (``RuntimeError`` before send).
        """
        max_attempts = max(1, self._config.retry_max + 1)
        last_resp: httpx.Response | None = None
        for attempt in range(max_attempts):
            try:
                resp = self._send(method, path, params, json_body, headers)
            except httpx.TransportError as exc:
                if attempt >= max_attempts - 1:
                    raise
                delay = self._retry_delay(attempt, None)
                logger.warning(
                    "dtrack: transport error on %s %s (attempt %d/%d): %s; "
                    "sleeping %.2fs",
                    method, path, attempt + 1, max_attempts, exc, delay,
                )
                self._sleep(delay)
                continue
            last_resp = resp
            if (
                resp.status_code not in _RETRYABLE_STATUS
                or attempt >= max_attempts - 1
            ):
                return resp
            delay = self._retry_delay(attempt, resp.headers.get("Retry-After"))
            logger.warning(
                "dtrack: HTTP %d on %s %s (attempt %d/%d); sleeping %.2fs",
                resp.status_code, method, path, attempt + 1, max_attempts, delay,
            )
            self._sleep(delay)
        assert last_resp is not None
        return last_resp

    def _retry_delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after is not None:
            try:
                parsed = float(retry_after)
                if parsed >= 0:
                    return min(parsed, _RETRY_AFTER_CAP_SECONDS)
            except ValueError:
                pass
        base = max(0.0, self._config.retry_backoff_ms / 1000.0)
        delay = base * (2 ** attempt) + random.uniform(0, base)
        return min(delay, _RETRY_AFTER_CAP_SECONDS)

    @staticmethod
    def _sleep(seconds: float) -> None:
        time.sleep(seconds)

    def _send(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        json_body: dict[str, Any] | None,
        headers: dict[str, str],
    ) -> httpx.Response:
        self._guard(method, path)
        return self._client.request(
            method,
            path,
            params=params,
            json=json_body,
            headers=headers,
        )

    @classmethod
    def _guard(cls, method: str, path: str) -> None:
        """Enforce the data-plane whitelist.

        GET is allowed on any path. Write methods (PUT/POST) are allowed
        only on the exact paths listed in ``_WRITE_ALLOWED``. Everything
        else raises. The login endpoint is handled in ``_login`` and
        deliberately bypasses this guard.
        """
        if method == "GET":
            return
        allowed_paths = cls._WRITE_ALLOWED.get(method)
        if allowed_paths is not None and path in allowed_paths:
            return
        allowed_repr = ", ".join(
            f"{m} {p}"
            for m, paths in sorted(cls._WRITE_ALLOWED.items())
            for p in sorted(paths)
        )
        raise RuntimeError(
            f"dtrack-mcp: refused {method} {path}; allowed: GET *, {allowed_repr}"
        )

    def _auth_headers(self) -> dict[str, str]:
        if self._config.has_api_key():
            assert self._config.api_key is not None
            return {"X-Api-Key": self._config.api_key}
        return {"Authorization": f"Bearer {self._get_jwt()}"}

    def _get_jwt(self) -> str:
        if self._jwt is None:
            self._jwt = self._login()
        return self._jwt

    def _login(self) -> str:
        # The login endpoint is authentication, not data mutation. It
        # does not modify Dependency-Track state. Deliberately bypasses
        # _guard — the guard is for data-plane requests only.
        logger.info("dtrack: logging in as %s", self._config.username)
        resp = self._client.post(
            self._LOGIN_PATH,
            data={
                "username": self._config.username or "",
                "password": self._config.password or "",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 200:
            raise DTrackAuthError(
                f"login failed: HTTP {resp.status_code} {resp.text[:200]}"
            )
        token = resp.text.strip()
        if not token or token.count(".") != 2:
            raise DTrackAuthError(
                f"login returned unexpected body: {resp.text[:200]}"
            )
        return token

    def _maybe_check_version(self) -> None:
        """Fire a one-shot DT version probe on first successful request.

        Logs INFO for DT ≥ 4.14, WARNING for older versions (degraded
        mode: EPSS-for-GHSA and CVSSv4 may be missing). Never raises —
        a missing ``/version`` endpoint or any other error is logged at
        DEBUG and the check is marked done. Disable with
        ``DTRACK_SKIP_VERSION_CHECK=true`` (useful in offline tests).
        """
        if self._version_checked:
            return
        self._version_checked = True
        if os.environ.get("DTRACK_SKIP_VERSION_CHECK", "").lower() == "true":
            return
        try:
            raw = self._client.get(
                "/api/v1/version", headers=self._auth_headers()
            )
        except httpx.HTTPError as e:  # pragma: no cover - network edge
            logger.debug("dtrack: version probe failed: %s", e)
            return
        if raw.status_code != 200 or not raw.content:
            logger.debug("dtrack: /api/v1/version returned %s", raw.status_code)
            return
        try:
            info = raw.json()
        except ValueError:
            return
        version = str(info.get("version") or "").strip()
        if not version:
            return
        major, minor = _parse_minor(version)
        if (major, minor) >= (4, 14):
            logger.info("dtrack: Dependency-Track version %s", version)
        else:
            logger.warning(
                "dtrack: Dependency-Track %s < 4.14. EPSS for GHSA and "
                "CVSSv4 may be missing; distro qualifier matching falls "
                "back to plain name+version.",
                version,
            )

    @staticmethod
    def _raise_for_status(resp: httpx.Response, path: str) -> None:
        if resp.status_code < 400:
            return
        if resp.status_code in (401, 403):
            raise DTrackAuthError(
                f"{resp.status_code} on {path}: {resp.text[:200]}"
            )
        raise DTrackHTTPError(resp.status_code, resp.text[:200], path)
