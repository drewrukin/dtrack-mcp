"""Tests for the rate-limit / transient-failure retry layer in ``Connection``.

The retry layer sits between ``_request_with_auth_retry`` (which owns
401 → re-login) and ``_send`` (which owns the actual HTTP call and the
data-plane guard). It retries on HTTP 429, 502, 503, 504 and on
transport-level errors; it must NOT retry on 401, on other 4xx, or on
guard refusals.

Tests stub ``Connection._send`` to yield a deterministic sequence of
responses / exceptions, and replace ``Connection._sleep`` with a
recorder so assertions can inspect backoff timing without actually
waiting.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from dtrack_mcp.connection import (
    Connection,
    DTrackAuthError,
    DTrackConfig,
    DTrackHTTPError,
)


def _make_conn(retry_max: int = 3, retry_backoff_ms: int = 10) -> Connection:
    cfg = DTrackConfig(
        base_url="https://dt.example.invalid",
        api_key="test-key",
        retry_max=retry_max,
        retry_backoff_ms=retry_backoff_ms,
    )
    return Connection(cfg)


def _resp(status: int, body: bytes = b"{}", headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status_code=status, content=body, headers=headers or {})


def _stub_send(
    conn: Connection, monkeypatch: pytest.MonkeyPatch, sequence: list[Any]
) -> list[tuple[str, str]]:
    """Replace ``_send`` with an iterator over ``sequence``.

    Each element is either an ``httpx.Response`` (returned) or an
    ``Exception`` instance (raised). Captures every (method, path) call.
    """
    calls: list[tuple[str, str]] = []
    it = iter(sequence)

    def fake_send(method: str, path: str, params, json_body, headers) -> httpx.Response:
        calls.append((method, path))
        item = next(it)
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(conn, "_send", fake_send)
    return calls


def _stub_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(Connection, "_sleep", staticmethod(lambda s: slept.append(s)))
    return slept


# ---------------------------------------------------------------------
# Happy path — no retry needed
# ---------------------------------------------------------------------

def test_no_retry_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _make_conn()
    calls = _stub_send(conn, monkeypatch, [_resp(200, b'{"ok":true}')])
    slept = _stub_sleep(monkeypatch)
    assert conn.get("/api/v1/project") == {"ok": True}
    assert len(calls) == 1
    assert slept == []


# ---------------------------------------------------------------------
# Retryable status codes
# ---------------------------------------------------------------------

@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_retry_on_transient_then_success(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    conn = _make_conn(retry_max=3, retry_backoff_ms=10)
    calls = _stub_send(conn, monkeypatch, [_resp(status), _resp(200, b'{"ok":1}')])
    slept = _stub_sleep(monkeypatch)
    assert conn.get("/api/v1/project") == {"ok": 1}
    assert len(calls) == 2
    assert len(slept) == 1
    assert slept[0] >= 0.010  # at least base backoff
    assert slept[0] <= 0.030  # base + jitter cap for attempt=0


def test_retry_exhausted_raises_dtrack_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _make_conn(retry_max=2, retry_backoff_ms=1)
    calls = _stub_send(conn, monkeypatch, [_resp(503), _resp(503), _resp(503)])
    _stub_sleep(monkeypatch)
    with pytest.raises(DTrackHTTPError) as exc:
        conn.get("/api/v1/project")
    assert exc.value.status_code == 503
    assert len(calls) == 3  # retry_max=2 => 3 total attempts


# ---------------------------------------------------------------------
# Non-retryable: 4xx (except 429), 2xx
# ---------------------------------------------------------------------

@pytest.mark.parametrize("status", [400, 404, 405, 409, 422, 500])
def test_non_retryable_status_not_retried(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    conn = _make_conn()
    calls = _stub_send(conn, monkeypatch, [_resp(status)])
    slept = _stub_sleep(monkeypatch)
    with pytest.raises(DTrackHTTPError):
        conn.get("/api/v1/project")
    assert len(calls) == 1
    assert slept == []


def test_401_not_retried_by_rate_limit_layer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """401 is handled by the auth-retry layer, not the rate-limit layer.

    With API-key auth (no JWT), a 401 must propagate as DTrackAuthError
    after a single send, not be retried as if transient.
    """
    conn = _make_conn()
    calls = _stub_send(conn, monkeypatch, [_resp(401)])
    slept = _stub_sleep(monkeypatch)
    with pytest.raises(DTrackAuthError):
        conn.get("/api/v1/project")
    assert len(calls) == 1
    assert slept == []


# ---------------------------------------------------------------------
# Retry-After header
# ---------------------------------------------------------------------

def test_retry_after_numeric_respected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _make_conn(retry_max=3, retry_backoff_ms=10)
    calls = _stub_send(
        conn,
        monkeypatch,
        [_resp(429, headers={"Retry-After": "2"}), _resp(200, b'{}')],
    )
    slept = _stub_sleep(monkeypatch)
    conn.get("/api/v1/project")
    assert slept == [2.0]


def test_retry_after_capped_at_60s(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _make_conn(retry_max=3, retry_backoff_ms=10)
    _stub_send(
        conn,
        monkeypatch,
        [_resp(503, headers={"Retry-After": "9999"}), _resp(200, b'{}')],
    )
    slept = _stub_sleep(monkeypatch)
    conn.get("/api/v1/project")
    assert slept == [60.0]


def test_retry_after_negative_falls_back_to_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed ``Retry-After: -5`` must not be passed to ``time.sleep``
    (would raise ValueError). The code guards with ``parsed >= 0`` and
    falls back to exponential backoff.
    """
    conn = _make_conn(retry_max=3, retry_backoff_ms=100)
    _stub_send(
        conn,
        monkeypatch,
        [_resp(503, headers={"Retry-After": "-5"}), _resp(200, b'{}')],
    )
    slept = _stub_sleep(monkeypatch)
    conn.get("/api/v1/project")
    assert 0.100 <= slept[0] <= 0.200
    assert slept[0] >= 0  # would be caught by time.sleep anyway, but double-lock


def test_retry_after_nonnumeric_falls_back_to_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _make_conn(retry_max=3, retry_backoff_ms=100)
    _stub_send(
        conn,
        monkeypatch,
        [
            _resp(503, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
            _resp(200, b'{}'),
        ],
    )
    slept = _stub_sleep(monkeypatch)
    conn.get("/api/v1/project")
    # Falls back to exponential backoff: base=0.1, attempt=0 → [0.1, 0.2)
    assert 0.100 <= slept[0] <= 0.200


# ---------------------------------------------------------------------
# Transport errors (connection refused, read timeout)
# ---------------------------------------------------------------------

def test_transport_error_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _make_conn(retry_max=3, retry_backoff_ms=1)
    calls = _stub_send(
        conn,
        monkeypatch,
        [httpx.ConnectError("refused"), _resp(200, b'{}')],
    )
    _stub_sleep(monkeypatch)
    conn.get("/api/v1/project")
    assert len(calls) == 2


def test_transport_error_exhausted_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _make_conn(retry_max=2, retry_backoff_ms=1)
    err = httpx.ReadTimeout("timeout")
    _stub_send(conn, monkeypatch, [err, err, err])
    _stub_sleep(monkeypatch)
    with pytest.raises(httpx.ReadTimeout):
        conn.get("/api/v1/project")


# ---------------------------------------------------------------------
# Guard is not retried
# ---------------------------------------------------------------------

def test_retry_on_write_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retry must work through ``put_json`` (the analysis write path)
    just like it works through ``get``. This exercises the full chain:
    ``put_json → _request_with_auth_retry → _send_with_retry → _send``
    for a whitelisted write — 503 once, then 200 with the normalised
    analysis body.
    """
    conn = _make_conn(retry_max=2, retry_backoff_ms=5)
    calls = _stub_send(
        conn,
        monkeypatch,
        [_resp(503), _resp(200, b'{"state":"NOT_AFFECTED"}')],
    )
    _stub_sleep(monkeypatch)
    result = conn.put_json("/api/v1/analysis", {"state": "NOT_AFFECTED"})
    assert result == {"state": "NOT_AFFECTED"}
    assert len(calls) == 2
    assert all(c == ("PUT", "/api/v1/analysis") for c in calls)


def test_guard_refusal_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard failures raise RuntimeError BEFORE any send; the retry
    layer must propagate them immediately, never wrap them in backoff.
    """
    conn = _make_conn()
    slept = _stub_sleep(monkeypatch)
    with pytest.raises(RuntimeError, match="refused"):
        conn.put_json("/api/v1/evil", {"x": 1})
    assert slept == []


# ---------------------------------------------------------------------
# Backoff shape
# ---------------------------------------------------------------------

def test_exponential_backoff_grows(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _make_conn(retry_max=4, retry_backoff_ms=100)
    _stub_send(
        conn,
        monkeypatch,
        [_resp(503), _resp(503), _resp(503), _resp(200, b'{}')],
    )
    slept = _stub_sleep(monkeypatch)
    conn.get("/api/v1/project")
    # attempt=0 → [0.1, 0.2); attempt=1 → [0.2, 0.3); attempt=2 → [0.4, 0.5)
    assert len(slept) == 3
    assert 0.100 <= slept[0] < 0.200
    assert 0.200 <= slept[1] < 0.300
    assert 0.400 <= slept[2] < 0.500


def test_computed_backoff_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    """With large ``retry_backoff_ms`` + deep ``attempt``, the raw
    exponential would be huge; the 60 s cap prevents an accidental
    multi-day wait.
    """
    conn = _make_conn(retry_max=10, retry_backoff_ms=5000)  # base=5s
    # At attempt=5: 5 * 32 = 160s, capped to 60.
    delay = conn._retry_delay(5, None)
    assert delay == pytest.approx(60.0, rel=0)


def test_negative_backoff_ms_clamped_to_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A misconfigured ``DTRACK_RETRY_BACKOFF_MS=-500`` must not produce
    a negative sleep (``time.sleep`` would raise). The base is clamped
    to 0, which gives an immediate retry — the contract is: bad config
    degrades to no-delay, never to a crash.
    """
    conn = _make_conn(retry_max=2, retry_backoff_ms=-500)
    delay = conn._retry_delay(0, None)
    assert delay == 0.0


def test_retry_max_zero_means_no_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _make_conn(retry_max=0, retry_backoff_ms=10)
    calls = _stub_send(conn, monkeypatch, [_resp(503)])
    slept = _stub_sleep(monkeypatch)
    with pytest.raises(DTrackHTTPError):
        conn.get("/api/v1/project")
    assert len(calls) == 1
    assert slept == []


# ---------------------------------------------------------------------
# Env-config wiring
# ---------------------------------------------------------------------

def test_from_env_reads_retry_knobs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DTRACK_URL", "https://dt.example.invalid")
    monkeypatch.setenv("DTRACK_API_KEY", "k")
    monkeypatch.setenv("DTRACK_RETRY_MAX", "7")
    monkeypatch.setenv("DTRACK_RETRY_BACKOFF_MS", "250")
    cfg = DTrackConfig.from_env()
    assert cfg.retry_max == 7
    assert cfg.retry_backoff_ms == 250


def test_from_env_retry_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DTRACK_URL", "https://dt.example.invalid")
    monkeypatch.setenv("DTRACK_API_KEY", "k")
    monkeypatch.delenv("DTRACK_RETRY_MAX", raising=False)
    monkeypatch.delenv("DTRACK_RETRY_BACKOFF_MS", raising=False)
    cfg = DTrackConfig.from_env()
    assert cfg.retry_max == 3
    assert cfg.retry_backoff_ms == 500
