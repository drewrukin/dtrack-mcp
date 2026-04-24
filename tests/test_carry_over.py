"""Unit tests for ``carry_over_triage`` — skip rules and mode behavior.

All tests bypass the HTTP layer by monkeypatching ``_fetch_all_findings``,
``_safe_get_analysis``, and ``set_analysis``. This keeps the focus on
carry-over decision logic, not JSON plumbing.
"""

from __future__ import annotations

from typing import Any

import pytest

from dtrack_mcp import api
from dtrack_mcp.connection import DTrackError
from dtrack_mcp.models import (
    NormalizedAnalysis,
    NormalizedComponent,
    NormalizedFinding,
)


def _comp(uuid: str, name: str = "libfoo", version: str = "1.0") -> NormalizedComponent:
    return {
        "uuid": uuid, "name": name, "version": version, "group": None,
        "purl": f"pkg:npm/{name}@{version}",
        "purl_type": "npm", "purl_namespace": None,
        "purl_name": name, "purl_version": version,
        "purl_qualifiers": {}, "latest_version": None,
    }


def _finding(
    vuln_id: str,
    comp: NormalizedComponent,
    *,
    state: str = "NOT_SET",
    source: str = "NVD",
) -> NormalizedFinding:
    return {
        "vulnerability": {
            "uuid": f"v-{vuln_id}", "source": source, "vuln_id": vuln_id,
            "severity": "HIGH",
            "cvss_v3_score": 7.5, "cvss_v3_vector": None,
            "cvss_v4_score": None, "cvss_v4_vector": None,
            "cwes": [], "epss_score": None, "in_kev": False, "aliases": [],
        },
        "component": comp,
        "analysis": {"state": state, "justification": None,  # type: ignore[typeddict-item]
                     "is_suppressed": False},
        "attributed_on": None,
    }


def _analysis(state: str, justification: str | None = "CODE_NOT_REACHABLE",
              comments: list[dict] | None = None) -> NormalizedAnalysis:
    return {
        "state": state,  # type: ignore[typeddict-item]
        "justification": justification, "response": None, "details": "from source",
        "is_suppressed": False,
        "comments": comments or [{"commenter": "human", "timestamp": None,
                                  "comment": "legit, not reachable"}],
    }


class _FakeConn:
    def __init__(self) -> None:
        self.analysis_writes: list[dict[str, Any]] = []

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if path.startswith("/api/v1/project/"):
            uuid = path.rsplit("/", 1)[-1]
            return {"uuid": uuid, "name": "demo",
                    "version": "1.0" if uuid == "S" else "2.0",
                    "classifier": "APPLICATION", "active": True, "metrics": {}}
        return None


def _install(
    monkeypatch,
    src: list[NormalizedFinding],
    tgt: list[NormalizedFinding],
    analyses: dict[str, NormalizedAnalysis] | None = None,
    conn: _FakeConn | None = None,
) -> _FakeConn:
    monkeypatch.setattr(
        api, "_fetch_all_findings",
        lambda _c, pid, *, suppressed: src if pid == "S" else tgt,
    )
    analyses = analyses or {}

    def fake_analysis(_c, _project, finding):
        return analyses.get(finding["vulnerability"]["vuln_id"])

    monkeypatch.setattr(api, "_safe_get_analysis", fake_analysis)

    conn = conn or _FakeConn()

    def fake_set_analysis(_c, **kw):
        conn.analysis_writes.append(kw)
        return {"state": kw["state"], "justification": kw.get("justification"),
                "response": None, "details": kw.get("details"),
                "is_suppressed": False, "comments": []}

    monkeypatch.setattr(api, "set_analysis", fake_set_analysis)
    return conn


# ---------------------------------------------------------------------------
# dry_run vs exact
# ---------------------------------------------------------------------------


def test_dry_run_never_writes(monkeypatch):
    c = _comp("c1")
    src = [_finding("CVE-1", c, state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", _comp("c2"))]
    conn = _install(monkeypatch, src, tgt,
                    {"CVE-1": _analysis("NOT_AFFECTED")})

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T", mode="dry_run",
    )
    assert result["mode"] == "dry_run"
    assert result["transferred"] == 1
    assert conn.analysis_writes == []


def test_exact_mode_writes_analysis(monkeypatch):
    c = _comp("c1")
    src = [_finding("CVE-1", c, state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", _comp("c2"))]
    conn = _install(monkeypatch, src, tgt,
                    {"CVE-1": _analysis("NOT_AFFECTED")})

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T", mode="exact",
    )
    assert result["transferred"] == 1
    assert len(conn.analysis_writes) == 1
    w = conn.analysis_writes[0]
    assert w["state"] == "NOT_AFFECTED"
    assert w["project_uuid"] == "T"
    assert "[dtrack-mcp]" in w["comment"]
    assert "Match: exact_purl" in w["comment"]


def test_invalid_mode_raises(monkeypatch):
    _install(monkeypatch, [], [])
    with pytest.raises(DTrackError):
        api.carry_over_triage(
            _FakeConn(), source_project_uuid="S", target_project_uuid="T",
            mode="please_run",
        )


# ---------------------------------------------------------------------------
# Skip rules
# ---------------------------------------------------------------------------


def test_skip_when_source_analysis_is_not_set(monkeypatch):
    """Source NOT_SET → nothing to transfer."""
    src = [_finding("CVE-1", _comp("c1"), state="NOT_SET")]
    tgt = [_finding("CVE-1", _comp("c2"))]
    conn = _install(monkeypatch, src, tgt, {"CVE-1": _analysis("NOT_SET")})

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T", mode="exact",
    )
    assert result["transferred"] == 0
    assert conn.analysis_writes == []


def test_skip_when_target_already_triaged_and_no_overwrite(monkeypatch):
    src = [_finding("CVE-1", _comp("c1"), state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", _comp("c2"), state="EXPLOITABLE")]
    conn = _install(monkeypatch, src, tgt,
                    {"CVE-1": _analysis("NOT_AFFECTED")})

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T",
        mode="exact", overwrite_any=False,
    )
    assert result["transferred"] == 0
    assert result["skipped"] == 1
    assert "EXPLOITABLE" in result["details"][0]["reason"]


def test_overwrite_any_forces_write_over_existing_triage(monkeypatch):
    src = [_finding("CVE-1", _comp("c1"), state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", _comp("c2"), state="EXPLOITABLE")]
    conn = _install(monkeypatch, src, tgt,
                    {"CVE-1": _analysis("NOT_AFFECTED")})

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T",
        mode="exact", overwrite_any=True,
    )
    assert result["transferred"] == 1
    assert conn.analysis_writes[0]["state"] == "NOT_AFFECTED"


def test_overwrite_not_set_false_skips_even_not_set_targets(monkeypatch):
    src = [_finding("CVE-1", _comp("c1"), state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", _comp("c2"), state="NOT_SET")]
    conn = _install(monkeypatch, src, tgt,
                    {"CVE-1": _analysis("NOT_AFFECTED")})

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T",
        mode="exact", overwrite_not_set=False,
    )
    assert result["transferred"] == 0
    assert result["skipped"] == 1


# ---------------------------------------------------------------------------
# max_operations guard
# ---------------------------------------------------------------------------


def test_max_operations_cap_blocks_exact_mode(monkeypatch):
    src = [_finding(f"CVE-{i}", _comp(f"c{i}"), state="NOT_AFFECTED")
           for i in range(10)]
    tgt = [_finding(f"CVE-{i}", _comp(f"t{i}")) for i in range(10)]
    analyses = {f"CVE-{i}": _analysis("NOT_AFFECTED") for i in range(10)}
    conn = _install(monkeypatch, src, tgt, analyses)

    with pytest.raises(DTrackError, match="max_operations"):
        api.carry_over_triage(
            conn, source_project_uuid="S", target_project_uuid="T",
            mode="exact", max_operations=3,
        )
    assert conn.analysis_writes == []


def test_max_operations_not_enforced_in_dry_run(monkeypatch):
    src = [_finding(f"CVE-{i}", _comp(f"c{i}"), state="NOT_AFFECTED")
           for i in range(10)]
    tgt = [_finding(f"CVE-{i}", _comp(f"t{i}")) for i in range(10)]
    analyses = {f"CVE-{i}": _analysis("NOT_AFFECTED") for i in range(10)}
    conn = _install(monkeypatch, src, tgt, analyses)

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T",
        mode="dry_run", max_operations=3,
    )
    assert result["transferred"] == 10


# ---------------------------------------------------------------------------
# include_updated_components
# ---------------------------------------------------------------------------


def test_updated_component_excluded_by_default(monkeypatch):
    src = [_finding("CVE-1", _comp("c1", "lib", "1.0"), state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", _comp("c2", "lib", "2.0"))]
    conn = _install(monkeypatch, src, tgt,
                    {"CVE-1": _analysis("NOT_AFFECTED")})

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T", mode="exact",
    )
    assert result["transferred"] == 0
    assert conn.analysis_writes == []


def test_updated_component_included_when_flag_set(monkeypatch):
    src = [_finding("CVE-1", _comp("c1", "lib", "1.0"), state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", _comp("c2", "lib", "2.0"))]
    conn = _install(monkeypatch, src, tgt,
                    {"CVE-1": _analysis("NOT_AFFECTED")})

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T",
        mode="exact", include_updated_components=True,
    )
    assert result["transferred"] == 1


# ---------------------------------------------------------------------------
# Comment format
# ---------------------------------------------------------------------------


def test_carry_comment_includes_prefix_source_and_match_reason(monkeypatch):
    src = [_finding("CVE-1", _comp("c1"), state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", _comp("c2"))]
    conn = _install(
        monkeypatch, src, tgt,
        {"CVE-1": _analysis("NOT_AFFECTED",
                            comments=[{"commenter": "a", "timestamp": None,
                                       "comment": "verified upstream"}])},
    )

    api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T",
        mode="exact", comment_prefix="[CUSTOM]",
    )
    c = conn.analysis_writes[0]["comment"]
    assert c.startswith("[CUSTOM]")
    assert "Carried from demo" in c
    assert "Match: exact_purl" in c
    assert "verified upstream" in c


# ---------------------------------------------------------------------------
# failed write accounting
# ---------------------------------------------------------------------------


def test_failed_write_counted_and_does_not_abort(monkeypatch):
    src = [
        _finding("CVE-1", _comp("c1"), state="NOT_AFFECTED"),
        _finding("CVE-2", _comp("c3", "other"), state="NOT_AFFECTED"),
    ]
    tgt = [
        _finding("CVE-1", _comp("c2")),
        _finding("CVE-2", _comp("c4", "other")),
    ]
    conn = _install(monkeypatch, src, tgt,
                    {"CVE-1": _analysis("NOT_AFFECTED"),
                     "CVE-2": _analysis("NOT_AFFECTED")})

    calls = {"n": 0}

    def flaky_set(_c, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise DTrackError("HTTP 500 boom")
        conn.analysis_writes.append(kw)
        return {"state": kw["state"], "justification": None, "response": None,
                "details": None, "is_suppressed": False, "comments": []}

    monkeypatch.setattr(api, "set_analysis", flaky_set)

    result = api.carry_over_triage(
        conn, source_project_uuid="S", target_project_uuid="T", mode="exact",
    )
    assert result["failed"] == 1
    assert result["transferred"] == 1
    failed_item = next(d for d in result["details"] if d["action"] == "failed")
    assert "boom" in failed_item["error"]
