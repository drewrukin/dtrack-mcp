"""Tests for ``Connection._guard`` — the (method, path) allowlist.

The guard is the mechanical enforcement of ``feedback_dtrack_readonly.md``
in this repo: any data-plane request that is not on the allowlist must
raise ``RuntimeError`` before it reaches the network. These tests lock
the allowlist to exactly what is documented: GET on any path, PUT on
``/api/v1/analysis``, POST on ``/api/v1/bom`` (v0.2 upload_bom).
Everything else fails closed.

Dependency-Track v4 records analysis decisions via ``PUT /api/v1/analysis``
(not POST). An earlier whitelist allowed POST and passed these tests in
isolation, but real DT returned HTTP 405 — the unit test validated its
own wrong model instead of the server contract. The allowlist is now
PUT, and the refused-combinations parametrize explicitly locks POST on
``/api/v1/analysis`` out again.
"""

from __future__ import annotations

import pytest

from dtrack_mcp.connection import Connection


def test_get_any_path_allowed() -> None:
    Connection._guard("GET", "/api/v1/project")
    Connection._guard("GET", "/api/v1/finding/project/abc-123")
    Connection._guard("GET", "/api/v1/analysis")
    Connection._guard("GET", "/api/version")


def test_put_analysis_allowed() -> None:
    Connection._guard("PUT", "/api/v1/analysis")


def test_post_bom_allowed() -> None:
    # v0.2 upload_bom: DT accepts CycloneDX/SPDX payloads as JSON on POST.
    Connection._guard("POST", "/api/v1/bom")


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/v1/analysis"),  # DT uses PUT, not POST — lock POST out
        ("POST", "/api/v1/project"),  # auto_create goes through /api/v1/bom
        ("POST", "/api/v1/vulnerability"),  # never allowed
        ("POST", "/api/v1/user/login"),  # login bypasses guard in _login
        ("POST", "/api/v1/bom/"),  # exact-match: trailing slash blocked
        ("PUT", "/api/v1/bom"),  # POST-only
        ("PUT", "/api/v1/analysis/suppress"),
        ("PUT", "/api/v1/project"),
        ("PATCH", "/api/v1/analysis"),
        ("DELETE", "/api/v1/analysis"),
        ("DELETE", "/api/v1/project/abc"),
        ("HEAD", "/api/v1/project"),
        ("OPTIONS", "/api/v1/project"),
    ],
)
def test_other_combinations_refused(method: str, path: str) -> None:
    with pytest.raises(RuntimeError, match="refused"):
        Connection._guard(method, path)


def test_put_analysis_case_sensitive_method() -> None:
    # The guard compares methods case-sensitively. httpx always sends
    # upper-case, so lower-case "put" is a bug signal, not a usage
    # mode — refuse it.
    with pytest.raises(RuntimeError):
        Connection._guard("put", "/api/v1/analysis")


def test_put_allowlist_is_exact_match_not_prefix() -> None:
    # A prefix match would open up things like
    # /api/v1/analysis/suppress, which is not what we want.
    with pytest.raises(RuntimeError):
        Connection._guard("PUT", "/api/v1/analysis/")
    with pytest.raises(RuntimeError):
        Connection._guard("PUT", "/api/v1/analysisX")
