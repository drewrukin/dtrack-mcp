"""Authentication path coverage for ``Connection``.

Existing tests (test_retry, test_guard, test_v04, ...) only exercise
the API-key auth path. This file locks the JWT/login flow:

  * ``_login`` — form-encoded POST, token validation, failure modes.
  * ``_auth_headers`` — API-key precedence, Bearer fallback.
  * 401 re-login behaviour — JWT is cleared and refetched once;
    API-key auth has no re-login and surfaces 401 as DTrackAuthError.
  * Missing credentials raise at ``Connection.__init__``.
  * ``from_env`` picks the right mode based on env vars.

Tests stub either ``Connection._send`` (for request-level scenarios)
or ``Connection._client`` (for login, which bypasses ``_send``).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from dtrack_mcp.connection import (
    Connection,
    DTrackAuthError,
    DTrackConfig,
    DTrackError,
)


def _resp(status: int, text: str = "", body: bytes | None = None) -> httpx.Response:
    if body is None:
        body = text.encode()
    return httpx.Response(status_code=status, content=body)


# ---------------------------------------------------------------------------
# Config / missing creds
# ---------------------------------------------------------------------------


def test_missing_credentials_raises_on_construction() -> None:
    cfg = DTrackConfig(base_url="https://dt.example.invalid")
    with pytest.raises(DTrackError, match="no credentials"):
        Connection(cfg)


def test_has_api_key_and_has_login_flags() -> None:
    assert DTrackConfig(base_url="x", api_key="k").has_api_key()
    assert not DTrackConfig(base_url="x", api_key="k").has_login()
    assert DTrackConfig(base_url="x", username="u", password="p").has_login()
    assert not DTrackConfig(base_url="x", username="u", password="p").has_api_key()
    assert not DTrackConfig(base_url="x").has_api_key()
    assert not DTrackConfig(base_url="x").has_login()


def test_from_env_prefers_api_key_when_both_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DTRACK_URL", "https://dt.example.invalid")
    monkeypatch.setenv("DTRACK_API_KEY", "odt_key")
    monkeypatch.setenv("DTRACK_USER", "u")
    monkeypatch.setenv("DTRACK_PASSWORD", "p")
    cfg = DTrackConfig.from_env()
    assert cfg.has_api_key()
    assert cfg.has_login()


def test_from_env_only_login(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DTRACK_URL", "https://dt.example.invalid")
    monkeypatch.delenv("DTRACK_API_KEY", raising=False)
    monkeypatch.setenv("DTRACK_USER", "u")
    monkeypatch.setenv("DTRACK_PASSWORD", "p")
    cfg = DTrackConfig.from_env()
    assert not cfg.has_api_key()
    assert cfg.has_login()


# ---------------------------------------------------------------------------
# _auth_headers — which header, which path
# ---------------------------------------------------------------------------


def test_auth_headers_uses_api_key_when_set() -> None:
    conn = Connection(DTrackConfig(base_url="https://x", api_key="odt_key"))
    headers = conn._auth_headers()
    assert headers == {"X-Api-Key": "odt_key"}


def test_auth_headers_uses_bearer_jwt_for_login_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = Connection(DTrackConfig(base_url="https://x", username="u", password="p"))
    monkeypatch.setattr(conn, "_login", lambda: "aaa.bbb.ccc")
    headers = conn._auth_headers()
    assert headers == {"Authorization": "Bearer aaa.bbb.ccc"}


def test_auth_headers_api_key_wins_when_both_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = Connection(
        DTrackConfig(base_url="https://x", api_key="odt_k", username="u", password="p")
    )
    # _login must never be called when api_key is present.
    called = {"yes": False}
    monkeypatch.setattr(conn, "_login", lambda: called.__setitem__("yes", True) or "j.w.t")
    headers = conn._auth_headers()
    assert headers == {"X-Api-Key": "odt_k"}
    assert called["yes"] is False


# ---------------------------------------------------------------------------
# _login — POST body, token validation, error paths
# ---------------------------------------------------------------------------


class _LoginClient:
    """Minimal stand-in for httpx.Client capturing the login POST."""

    def __init__(self, response: httpx.Response) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def post(self, path: str, **kw: Any) -> httpx.Response:
        self.calls.append({"path": path, **kw})
        return self.response

    def request(self, *a: Any, **kw: Any) -> httpx.Response:  # unused here
        raise AssertionError("request() must not be called during _login test")

    def close(self) -> None:
        pass


def _login_conn(
    response: httpx.Response, *, username: str = "u", password: str = "p"
) -> tuple[Connection, _LoginClient]:
    conn = Connection(
        DTrackConfig(base_url="https://x", username=username, password=password)
    )
    client = _LoginClient(response)
    conn._client = client  # type: ignore[assignment]
    return conn, client


def test_login_posts_form_urlencoded_and_returns_jwt() -> None:
    conn, client = _login_conn(_resp(200, "header.payload.sig"))
    token = conn._login()
    assert token == "header.payload.sig"
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["path"] == "/api/v1/user/login"
    assert call["data"] == {"username": "u", "password": "p"}
    assert call["headers"] == {"Content-Type": "application/x-www-form-urlencoded"}


def test_login_non_200_raises_auth_error() -> None:
    conn, _ = _login_conn(_resp(401, "bad creds"))
    with pytest.raises(DTrackAuthError, match="login failed"):
        conn._login()


def test_login_malformed_token_raises_auth_error() -> None:
    # token without two dots is not a JWT — DT sometimes returns an
    # error page with 200 when an upstream proxy strips the body type.
    conn, _ = _login_conn(_resp(200, "not-a-jwt"))
    with pytest.raises(DTrackAuthError, match="unexpected body"):
        conn._login()


def test_login_empty_body_raises_auth_error() -> None:
    conn, _ = _login_conn(_resp(200, ""))
    with pytest.raises(DTrackAuthError, match="unexpected body"):
        conn._login()


def test_jwt_is_cached_across_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_get_jwt`` must not hit ``_login`` on every header build — it
    caches the token. If this regresses, every single HTTP call becomes
    a double round-trip on login-mode auth.
    """
    conn = Connection(DTrackConfig(base_url="https://x", username="u", password="p"))
    login_calls = {"n": 0}

    def _fake_login() -> str:
        login_calls["n"] += 1
        return "a.b.c"

    monkeypatch.setattr(conn, "_login", _fake_login)
    conn._auth_headers()
    conn._auth_headers()
    conn._auth_headers()
    assert login_calls["n"] == 1


# ---------------------------------------------------------------------------
# 401 behaviour — re-login on JWT mode, hard fail on API-key mode
# ---------------------------------------------------------------------------


def _stub_send(
    conn: Connection, monkeypatch: pytest.MonkeyPatch, responses: list[httpx.Response]
) -> list[tuple[str, str]]:
    it = iter(responses)
    calls: list[tuple[str, str]] = []

    def fake_send(method: str, path: str, params, json_body, headers) -> httpx.Response:
        calls.append((method, path))
        return next(it)

    monkeypatch.setattr(conn, "_send", fake_send)
    return calls


def test_401_on_jwt_mode_refreshes_and_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = Connection(
        DTrackConfig(base_url="https://x", username="u", password="p", retry_max=0)
    )
    # Pre-fill JWT so the first request has one.
    conn._jwt = "old.token.sig"
    login_calls = {"n": 0}

    def _fake_login() -> str:
        login_calls["n"] += 1
        return "new.token.sig"

    monkeypatch.setattr(conn, "_login", _fake_login)

    calls = _stub_send(
        conn,
        monkeypatch,
        [_resp(401, body=b'{"error":"expired"}'), _resp(200, body=b'{"ok":1}')],
    )
    result = conn.get("/api/v1/project")
    assert result == {"ok": 1}
    assert len(calls) == 2                     # 401 → refresh → 200
    assert login_calls["n"] == 1               # _login called exactly once
    assert conn._jwt == "new.token.sig"        # JWT updated


def test_401_on_api_key_mode_surfaces_as_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With API-key auth there is no login to refresh. A 401 means the
    key is bad / revoked — fail loudly, do not loop.
    """
    conn = Connection(
        DTrackConfig(base_url="https://x", api_key="bad_key", retry_max=0)
    )
    calls = _stub_send(conn, monkeypatch, [_resp(401, body=b'{"error":"denied"}')])
    with pytest.raises(DTrackAuthError):
        conn.get("/api/v1/project")
    assert len(calls) == 1


def test_persistent_401_on_jwt_mode_eventually_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If DT returns 401 even after a fresh login (wrong password,
    revoked user), the client must stop — not loop forever.
    """
    conn = Connection(
        DTrackConfig(base_url="https://x", username="u", password="p", retry_max=0)
    )
    conn._jwt = "first.jwt.sig"
    monkeypatch.setattr(conn, "_login", lambda: "second.jwt.sig")
    _stub_send(
        conn,
        monkeypatch,
        [_resp(401, body=b"expired"), _resp(401, body=b"still-denied")],
    )
    with pytest.raises(DTrackAuthError):
        conn.get("/api/v1/project")
