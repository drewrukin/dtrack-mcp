"""Coverage for the five fixes found in the 2026-04-24 whole-package review.

Each test targets one specific fix so a future regression reintroduces
exactly the bug we just removed:

  1. ``search_vulnerability`` — a 5xx from per-project ``_fetch_all_findings``
     must propagate, not be silently swallowed.
  2. ``find_duplicate_analyses`` — same invariant for the
     ``_collect_other_project_duplicates`` bucket.
  3. ``carry_over_triage`` — ``src_analysis is None`` on a non-skipped
     candidate must raise ``DTrackError`` (was ``assert`` which disappears
     under ``python -O``).
  4. ``_clamp_page_size`` — accepts ``None`` / ``<=0`` and returns the
     default (the annotation now says ``int | None``).
  5. ``_safe_get_analysis`` — auth errors must propagate; only HTTP
     errors are swallowed to keep ``diff_findings`` resilient to 404s.
"""

from __future__ import annotations

from typing import Any

import pytest

from dtrack_mcp import api
from dtrack_mcp.connection import DTrackAuthError, DTrackError, DTrackHTTPError


def _comp(uuid: str = "C-1") -> dict[str, Any]:
    return {
        "uuid": uuid,
        "name": "libfoo",
        "version": "1.0",
        "group": None,
        "purl": "pkg:npm/libfoo@1.0",
        "purl_type": "npm",
        "purl_namespace": None,
        "purl_name": "libfoo",
        "purl_version": "1.0",
        "purl_qualifiers": {},
        "latest_version": None,
    }


def _finding(vuln_uuid: str = "V-1", vuln_id: str = "CVE-2024-1") -> dict[str, Any]:
    return {
        "vulnerability": {
            "uuid": vuln_uuid,
            "source": "NVD",
            "vuln_id": vuln_id,
            "severity": "HIGH",
            "cvss_v3_score": 7.5,
            "cvss_v3_vector": None,
            "cvss_v4_score": None,
            "cvss_v4_vector": None,
            "cwes": [],
            "epss_score": None,
            "in_kev": False,
            "aliases": [],
            "title": None,
            "description": None,
            "references": [],
        },
        "component": _comp(),
        "analysis": {
            "state": "NOT_SET",
            "justification": None,
            "is_suppressed": False,
        },
        "attributed_on": None,
    }


# ---------------------------------------------------------------------------
# Fix #1 — search_vulnerability propagates 5xx on per-project findings fetch
# ---------------------------------------------------------------------------

def test_search_vulnerability_propagates_5xx(monkeypatch: pytest.MonkeyPatch) -> None:
    vuln = {
        "uuid": "V-1", "source": "NVD", "vuln_id": "CVE-2024-1234",
        "severity": "HIGH", "cvss_v3_score": 7.5, "cvss_v3_vector": None,
        "cvss_v4_score": None, "cvss_v4_vector": None, "cvss_v2_score": None,
        "title": None, "description": None,
        "cwes": [], "epss_score": None, "epss_percentile": None,
        "in_kev": False, "published": None, "updated": None,
        "references": [], "aliases": [], "affected_components_count": None,
    }
    monkeypatch.setattr(api, "find_vulnerability", lambda _c, **kw: vuln)

    def boom(_c, _u, **kw):
        raise DTrackHTTPError(503, "service unavailable", "/api/v1/finding/...")

    monkeypatch.setattr(api, "_fetch_all_findings", boom)

    class _Conn:
        def get(self, path: str, params: Any = None) -> Any:
            if "/projects" in path:
                return [{"uuid": "P-OTHER", "name": "other", "active": True, "metrics": {}}]
            return None

    with pytest.raises(DTrackHTTPError) as exc:
        api.search_vulnerability(_Conn(), vuln_id="CVE-2024-1234")  # type: ignore[arg-type]
    assert exc.value.status_code == 503


def test_search_vulnerability_still_swallows_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """Backward-compat: a 404 on per-project findings still lets the loop
    continue (the project is added with empty ``analyses`` — DT sometimes
    returns 404 for recently-deleted projects).
    """
    vuln = {
        "uuid": "V-1", "source": "NVD", "vuln_id": "CVE-2024-1234",
        "severity": "HIGH", "cvss_v3_score": 7.5, "cvss_v3_vector": None,
        "cvss_v4_score": None, "cvss_v4_vector": None, "cvss_v2_score": None,
        "title": None, "description": None,
        "cwes": [], "epss_score": None, "epss_percentile": None,
        "in_kev": False, "published": None, "updated": None,
        "references": [], "aliases": [], "affected_components_count": None,
    }
    monkeypatch.setattr(api, "find_vulnerability", lambda _c, **kw: vuln)
    monkeypatch.setattr(
        api,
        "_fetch_all_findings",
        lambda _c, _u, **kw: (_ for _ in ()).throw(
            DTrackHTTPError(404, "gone", "/finding")
        ),
    )

    class _Conn:
        def get(self, path: str, params: Any = None) -> Any:
            if "/projects" in path:
                return [{"uuid": "P-OTHER", "name": "other", "active": True, "metrics": {}}]
            return None

    result = api.search_vulnerability(_Conn(), vuln_id="CVE-2024-1234")  # type: ignore[arg-type]
    assert result is not None
    assert result["total_projects"] == 1
    assert result["affected_projects"][0]["analyses"] == []


# ---------------------------------------------------------------------------
# Fix #2 — _collect_other_project_duplicates propagates 5xx
# ---------------------------------------------------------------------------

def test_find_duplicate_analyses_propagates_5xx_from_other_projects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _finding("V-1", "CVE-2024-1")
    monkeypatch.setattr(
        api, "_fetch_all_findings", _make_fetch_raising_on_other("P-OTHER")
    )
    monkeypatch.setattr(
        api, "get_analysis", lambda _c, **kw: {
            "state": "NOT_SET", "justification": None, "response": None,
            "details": None, "is_suppressed": False, "comments": [],
        },
    )

    class _Conn:
        def get(self, path: str, params: Any = None) -> Any:
            if path.endswith("/projects"):
                return [{"uuid": "P-OTHER", "name": "other", "active": True, "metrics": {}}]
            return None

    with pytest.raises(DTrackHTTPError) as exc:
        api.find_duplicate_analyses(
            _Conn(),  # type: ignore[arg-type]
            project_uuid="P-SRC",
            component_uuid="C-1",
            vulnerability_uuid="V-1",
        )
    assert exc.value.status_code == 500

    # Guard: make sure our fixture actually exercised the other-projects path.
    # (If the implementation short-circuits before, the raise-on-other helper
    # wouldn't even fire and the test would falsely pass.)
    del target  # appease linters — used only to define the finding shape


def _make_fetch_raising_on_other(bad_uuid: str):
    target = _finding("V-1", "CVE-2024-1")

    def _fetch(_conn, project_uuid, **kw):
        if project_uuid == bad_uuid:
            raise DTrackHTTPError(500, "boom", "/api/v1/finding/...")
        return [target]

    return _fetch


# ---------------------------------------------------------------------------
# Fix #3 — carry_over raises DTrackError instead of bare assert
# ---------------------------------------------------------------------------

def test_carry_over_raises_when_decide_action_corrupted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``_decide_action`` ever returns a non-skipped action with
    ``src_analysis is None``, carry_over must raise a DTrackError — not
    an AssertionError (which disappears under ``python -O``).
    """
    tf = _finding("V-1", "CVE-2024-1")

    fake_diff = {
        "carried": [
            {
                "target_finding": tf,
                "source_finding": tf,
                "source_analysis": None,
                "match_reason": "exact_purl",
            }
        ],
        "updated_component": [],
        "new": [],
        "gone": [],
        "source_project": {"uuid": "P-S", "name": "src", "version": "1.0"},
        "target_project": {"uuid": "P-T", "name": "src", "version": "2.0"},
        "stats": {"carried": 1, "updated_component": 0, "new": 0, "gone": 0},
        "warnings": [],
    }
    monkeypatch.setattr(api, "diff_findings", lambda *a, **kw: fake_diff)
    monkeypatch.setattr(
        api,
        "_decide_action",
        lambda *a, **kw: ("transfer", ""),  # lie: src_analysis is None but we say transfer
    )

    with pytest.raises(DTrackError, match="src_analysis is None"):
        api.carry_over_triage(
            conn=None,  # type: ignore[arg-type]
            source_project_uuid="P-S",
            target_project_uuid="P-T",
            mode="exact",
        )


# ---------------------------------------------------------------------------
# Fix #4 — _clamp_page_size accepts None and non-positive values
# ---------------------------------------------------------------------------

def test_clamp_page_size_none_returns_default() -> None:
    assert api._clamp_page_size(None, default=50) == 50


def test_clamp_page_size_zero_returns_default() -> None:
    assert api._clamp_page_size(0, default=50) == 50


def test_clamp_page_size_negative_returns_default() -> None:
    assert api._clamp_page_size(-10, default=50) == 50


def test_clamp_page_size_caps_at_max() -> None:
    assert api._clamp_page_size(10_000, default=50) == 500  # _MAX_PAGE_SIZE


def test_clamp_page_size_passes_through_valid() -> None:
    assert api._clamp_page_size(25, default=50) == 25


def test_clamp_pagination_accepts_none_page() -> None:
    page, size = api._clamp_pagination(None, None, default=50)
    assert page == 1
    assert size == 50


# ---------------------------------------------------------------------------
# Fix #5 — _safe_get_analysis swallows HTTP but NOT auth errors
# ---------------------------------------------------------------------------

def test_safe_get_analysis_swallows_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_http(*a: Any, **kw: Any) -> Any:
        raise DTrackHTTPError(404, "no analysis", "/api/v1/analysis")

    monkeypatch.setattr(api, "get_analysis", _raise_http)
    tf = _finding()
    result = api._safe_get_analysis(None, "P-1", tf)  # type: ignore[arg-type]
    assert result is None


def test_safe_get_analysis_propagates_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auth failures must not be hidden by diff_findings' optional
    source_analysis — the user needs to know creds are wrong, not see a
    silent empty diff.
    """
    def _raise_auth(*a: Any, **kw: Any) -> Any:
        raise DTrackAuthError("401 — token expired")

    monkeypatch.setattr(api, "get_analysis", _raise_auth)
    tf = _finding()
    with pytest.raises(DTrackAuthError):
        api._safe_get_analysis(None, "P-1", tf)  # type: ignore[arg-type]
