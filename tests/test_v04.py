"""Unit tests for v0.4+ additions.

Covers:
  * ``set_analysis`` with finding dict — uuid extraction + error paths
  * ``find_duplicate_analyses`` filters — states, only_analyzed,
    active_only, project_tag, and compact mode
  * ``resolve_project`` — UUID path, name+version path, error paths
  * ``find_vulnerability`` with explicit source
  * ``search_vulnerability`` — cross-project lookup

All tests bypass HTTP by monkeypatching ``_fetch_all_findings`` and
``get_analysis``. The ``vulnerability/source/*/vuln/*/projects`` endpoint
is faked through a tiny stand-in connection.
"""

from __future__ import annotations

from typing import Any

import pytest

from dtrack_mcp import api
from dtrack_mcp.connection import DTrackError, DTrackHTTPError


# ---------------------------------------------------------------------------
# Finding factory (shared across v0.4 tests)
# ---------------------------------------------------------------------------


def _comp(uuid: str, name: str = "libfoo", version: str = "1.0") -> dict[str, Any]:
    return {
        "uuid": uuid,
        "name": name,
        "version": version,
        "group": None,
        "purl": f"pkg:npm/{name}@{version}",
        "purl_type": "npm",
        "purl_namespace": None,
        "purl_name": name,
        "purl_version": version,
        "purl_qualifiers": {"distro": "bookworm", "arch": "amd64"},
        "latest_version": "2.0",
    }


def _finding(
    vuln_uuid: str,
    vuln_id: str,
    comp: dict[str, Any],
    *,
    source: str = "NVD",
    state: str = "NOT_SET",
    aliases: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "vulnerability": {
            "uuid": vuln_uuid,
            "source": source,
            "vuln_id": vuln_id,
            "severity": "HIGH",
            "cvss_v3_score": 7.5,
            "cvss_v3_vector": "AV:N/AC:L",
            "cvss_v4_score": None,
            "cvss_v4_vector": None,
            "cwes": [79],
            "epss_score": 0.1,
            "in_kev": False,
            "aliases": aliases or [],
            "title": "sample",
            "description": "A" * 500,
            "references": ["https://example.com/a", "https://example.com/b"],
        },
        "component": comp,
        "analysis": {
            "state": state,
            "justification": None,
            "is_suppressed": False,
        },
        "attributed_on": None,
    }


def _analysis(state: str, *, comment: str = "prior verdict") -> dict[str, Any]:
    return {
        "state": state,
        "justification": "CODE_NOT_REACHABLE" if state == "NOT_AFFECTED" else None,
        "response": None,
        "details": "free-form analysis text that can be long " * 10,
        "is_suppressed": False,
        "comments": [
            {"commenter": "human", "timestamp": None, "comment": comment},
        ],
    }


# ---------------------------------------------------------------------------
# set_analysis with finding dict (merged set_analysis_for_finding)
# ---------------------------------------------------------------------------


class _PutCapture:
    """Stub Connection that captures put_json calls."""

    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []

    def put_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        return {"analysisState": body.get("analysisState", "NOT_SET")}


def test_set_analysis_with_finding_extracts_uuids():
    conn = _PutCapture()
    finding = _finding("V-1", "CVE-2024-1", _comp("C-1"))
    api.set_analysis(
        conn,  # type: ignore[arg-type]
        project_uuid="P-1",
        finding=finding,  # type: ignore[arg-type]
        state="NOT_AFFECTED",
        justification="CODE_NOT_REACHABLE",
    )

    assert len(conn.bodies) == 1
    body = conn.bodies[0]
    assert body["project"] == "P-1"
    assert body["component"] == "C-1"
    assert body["vulnerability"] == "V-1"
    assert body["analysisState"] == "NOT_AFFECTED"
    assert body["analysisJustification"] == "CODE_NOT_REACHABLE"


def test_set_analysis_with_finding_forwards_optional_fields():
    conn = _PutCapture()
    api.set_analysis(
        conn,  # type: ignore[arg-type]
        project_uuid="P",
        finding=_finding("V", "CVE-X", _comp("C")),  # type: ignore[arg-type]
        state="EXPLOITABLE",
        response="WILL_NOT_FIX",
        details="notes",
        comment="appended",
        suppressed=True,
    )

    body = conn.bodies[0]
    assert body["analysisResponse"] == "WILL_NOT_FIX"
    assert body["analysisDetails"] == "notes"
    assert body["comment"] == "appended"
    assert body["isSuppressed"] is True


def test_set_analysis_with_finding_missing_component_uuid_raises():
    finding = _finding("V", "CVE-X", _comp("C"))
    finding["component"]["uuid"] = ""

    with pytest.raises(DTrackError, match="component.uuid"):
        api.set_analysis(
            None,  # type: ignore[arg-type]
            project_uuid="P",
            finding=finding,  # type: ignore[arg-type]
            state="NOT_AFFECTED",
        )


def test_set_analysis_with_finding_missing_vuln_uuid_raises():
    finding = _finding("", "CVE-X", _comp("C"))

    with pytest.raises(DTrackError, match="vulnerability.uuid"):
        api.set_analysis(
            None,  # type: ignore[arg-type]
            project_uuid="P",
            finding=finding,  # type: ignore[arg-type]
            state="NOT_AFFECTED",
        )


def test_set_analysis_without_finding_or_uuids_raises():
    with pytest.raises(DTrackError, match="component_uuid and vulnerability_uuid"):
        api.set_analysis(
            None,  # type: ignore[arg-type]
            project_uuid="P",
            state="NOT_AFFECTED",
        )


# ---------------------------------------------------------------------------
# find_duplicate_analyses: state / precedence / active_only / tag / compact
# ---------------------------------------------------------------------------


class _DupConn:
    """Returns per-alias project lists via .get(); rest is patched."""

    def __init__(self, projects_per_alias: dict[str, list[dict[str, Any]]]) -> None:
        self.projects_per_alias = projects_per_alias

    def get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> Any:
        if "/projects" in path:
            key = path.split("/source/")[-1].replace("/projects", "")
            return self.projects_per_alias.get(key, [])
        return None


def _install_dup_mocks(
    monkeypatch,
    *,
    project_findings_by_uuid: dict[str, list[dict[str, Any]]],
    analyses_by_uuid: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    def fake_fetch(_c, pid, *, suppressed, include_details=False):
        return project_findings_by_uuid.get(pid, [])

    def fake_get_analysis(_c, *, project_uuid, component_uuid, vulnerability_uuid):
        return analyses_by_uuid.get(
            (project_uuid, component_uuid, vulnerability_uuid),
            {
                "state": "NOT_SET",
                "justification": None,
                "response": None,
                "details": None,
                "is_suppressed": False,
                "comments": [],
            },
        )

    monkeypatch.setattr(api, "_fetch_all_findings", fake_fetch)
    monkeypatch.setattr(api, "get_analysis", fake_get_analysis)


def _dup_scenario(monkeypatch):
    """Build a scenario with aliases in same project + other projects."""
    tc = _comp("TC-1")
    target = _finding(
        "TV-1",
        "CVE-2024-1",
        tc,
        aliases=[{"source": "GITHUB", "vuln_id": "GHSA-xxx"}],
    )
    alias_peer = _finding(  # different uuid, linked via alias GHSA-xxx
        "TV-2",
        "GHSA-xxx",
        _comp("TC-2"),
        source="GITHUB",
        aliases=[{"source": "NVD", "vuln_id": "CVE-2024-1"}],
    )
    same_vuln_other_comp = _finding(
        "TV-1",
        "CVE-2024-1",
        _comp("TC-3"),
    )
    # Other projects hit the target's aliases
    op_active = _finding("V-OP-1", "CVE-2024-1", _comp("OC-1"))
    op_archived = _finding("V-OP-2", "CVE-2024-1", _comp("OC-2"))
    op_tagged = _finding("V-OP-3", "CVE-2024-1", _comp("OC-3"))

    project_findings = {
        "P-TARGET": [target, alias_peer, same_vuln_other_comp],
        "P-ACTIVE": [op_active],
        "P-ARCHIVED": [op_archived],
        "P-TAGGED": [op_tagged],
    }

    projects_per_alias = {
        "NVD/vuln/CVE-2024-1": [
            {"uuid": "P-ACTIVE", "name": "active-proj", "version": "1", "active": True, "tags": [{"name": "arenadata-release"}]},
            {"uuid": "P-ARCHIVED", "name": "archived-proj", "version": "0.9", "active": False, "tags": [{"name": "arenadata-release"}]},
            {"uuid": "P-TAGGED", "name": "tagged-proj", "version": "1", "active": True, "tags": [{"name": "other-tag"}]},
        ],
        "GITHUB/vuln/GHSA-xxx": [],
    }

    analyses = {
        # Target (same-project)
        ("P-TARGET", "TC-1", "TV-1"): _analysis("EXPLOITABLE"),
        ("P-TARGET", "TC-2", "TV-2"): _analysis("NOT_AFFECTED"),
        ("P-TARGET", "TC-3", "TV-1"): {  # NOT_SET, no comments
            "state": "NOT_SET",
            "justification": None,
            "response": None,
            "details": None,
            "is_suppressed": False,
            "comments": [],
        },
        # Other projects
        ("P-ACTIVE", "OC-1", "V-OP-1"): _analysis("NOT_AFFECTED"),
        ("P-ARCHIVED", "OC-2", "V-OP-2"): _analysis("FALSE_POSITIVE"),
        ("P-TAGGED", "OC-3", "V-OP-3"): _analysis("EXPLOITABLE"),
    }

    _install_dup_mocks(
        monkeypatch,
        project_findings_by_uuid=project_findings,
        analyses_by_uuid=analyses,
    )
    conn = _DupConn(projects_per_alias)
    return conn


def test_find_dup_no_filters_returns_all_buckets(monkeypatch):
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        active_only=False,  # include archived so we see full inventory
    )
    assert len(result["aliases_in_project"]) == 1  # TC-2/TV-2
    assert len(result["same_vuln_other_components"]) == 1  # TC-3/TV-1
    assert len(result["other_projects"]) == 3  # active + archived + tagged


def test_find_dup_states_filter_narrows_all_buckets(monkeypatch):
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        states=["NOT_AFFECTED"],
        active_only=False,
    )
    # aliases_in_project: TC-2/TV-2 has NOT_AFFECTED → kept
    assert len(result["aliases_in_project"]) == 1
    # same_vuln_other_components: TC-3/TV-1 has NOT_SET → dropped
    assert result["same_vuln_other_components"] == []
    # other_projects: only P-ACTIVE has NOT_AFFECTED
    assert [e["project"]["uuid"] for e in result["other_projects"]] == ["P-ACTIVE"]


def test_find_dup_only_analyzed_shorthand(monkeypatch):
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        only_analyzed=True,
        active_only=False,
    )
    # All NOT_SET entries dropped: same_vuln_other_components (TC-3)
    assert result["same_vuln_other_components"] == []
    assert len(result["aliases_in_project"]) == 1  # NOT_AFFECTED
    assert len(result["other_projects"]) == 3  # all three have triaged states


def test_find_dup_states_wins_over_only_analyzed(monkeypatch):
    """When both set, states is the full knob and only_analyzed is ignored."""
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        states=["NOT_SET"],  # explicit: include NOT_SET
        only_analyzed=True,  # would drop NOT_SET, but states wins
        active_only=False,
    )
    # same_vuln_other_components (TC-3 / NOT_SET) must be present
    assert len(result["same_vuln_other_components"]) == 1


def test_find_dup_active_only_default_drops_archived(monkeypatch):
    conn = _dup_scenario(monkeypatch)
    # Call without active_only override — default True
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
    )
    uuids = {e["project"]["uuid"] for e in result["other_projects"]}
    assert "P-ARCHIVED" not in uuids
    assert "P-ACTIVE" in uuids
    assert "P-TAGGED" in uuids


def test_find_dup_project_tag_filters_other_projects(monkeypatch):
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        project_tag="arenadata-release",
        active_only=False,
    )
    uuids = {e["project"]["uuid"] for e in result["other_projects"]}
    assert uuids == {"P-ACTIVE", "P-ARCHIVED"}


def test_find_dup_project_tag_case_insensitive(monkeypatch):
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        project_tag="ARENADATA-RELEASE",
        active_only=False,
    )
    assert len(result["other_projects"]) == 2


def test_find_dup_target_never_dropped_by_state_filter(monkeypatch):
    """target is what the caller asked about — filters must not eat it."""
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        states=["NOT_SET"],  # target is EXPLOITABLE — would be filtered
    )
    assert result["target"]["vulnerability"]["uuid"] == "TV-1"
    assert result["target"]["analysis"]["state"] == "EXPLOITABLE"


def test_find_dup_compact_strips_bulky_fields(monkeypatch):
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        active_only=False,
        compact=True,
    )
    # target
    t = result["target"]
    assert t["vulnerability"]["description"] is None
    assert t["vulnerability"]["title"] is None
    assert t["vulnerability"]["references"] == []
    assert t["vulnerability"]["cvss_v3_vector"] is None
    assert t["component"]["purl_qualifiers"] == {}
    assert t["component"]["latest_version"] is None
    assert t["analysis"]["details"] is None

    # other_projects entries too
    for entry in result["other_projects"]:
        assert entry["vulnerability"]["description"] is None
        assert entry["component"]["purl_qualifiers"] == {}
        assert entry["analysis"]["details"] is None


def test_find_dup_compact_truncates_long_comments(monkeypatch):
    long_comment = "X" * 500
    target = _finding("TV", "CVE-1", _comp("TC"))
    analyses = {
        ("P-TARGET", "TC", "TV"): {
            "state": "EXPLOITABLE",
            "justification": None,
            "response": None,
            "details": None,
            "is_suppressed": False,
            "comments": [
                {"commenter": "a", "timestamp": None, "comment": long_comment},
                {"commenter": "b", "timestamp": None, "comment": "short"},
            ],
        },
    }
    _install_dup_mocks(
        monkeypatch,
        project_findings_by_uuid={"P-TARGET": [target]},
        analyses_by_uuid=analyses,
    )
    conn = _DupConn({})
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC",
        vulnerability_uuid="TV",
        compact=True,
    )
    comments = result["target"]["analysis"]["comments"]
    assert comments[0]["comment"].endswith("...")
    assert len(comments[0]["comment"]) == 203  # 200 chars + "..."
    # Short comment must NOT be padded or truncated
    assert comments[1]["comment"] == "short"


def test_find_dup_preserves_core_signal_when_compact(monkeypatch):
    """Compact must keep what the triager needs: state, score, aliases, ids."""
    conn = _dup_scenario(monkeypatch)
    result = api.find_duplicate_analyses(
        conn,  # type: ignore[arg-type]
        project_uuid="P-TARGET",
        component_uuid="TC-1",
        vulnerability_uuid="TV-1",
        active_only=False,
        compact=True,
    )
    t = result["target"]
    assert t["vulnerability"]["vuln_id"] == "CVE-2024-1"
    assert t["vulnerability"]["severity"] == "HIGH"
    assert t["vulnerability"]["cvss_v3_score"] == 7.5
    assert t["vulnerability"]["cwes"] == [79]
    assert t["analysis"]["state"] == "EXPLOITABLE"
    assert t["component"]["uuid"] == "TC-1"
    assert t["component"]["purl"] is not None


# ---------------------------------------------------------------------------
# get_project (§14, v0.4.1 patch)
# ---------------------------------------------------------------------------


class _ProjectConn:
    """Stub Connection whose only purpose is to feed a canned GET response."""

    def __init__(self, response: Any = None, *, raise_status: int | None = None) -> None:
        self._response = response
        self._raise_status = raise_status
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        self.calls.append((path, params))
        if self._raise_status is not None:
            from dtrack_mcp.connection import DTrackHTTPError
            raise DTrackHTTPError(self._raise_status, "not found", path)
        return self._response


def test__get_project_returns_normalized_on_hit():
    raw = {
        "uuid": "P-ABC",
        "name": "adh",
        "version": "3.2.1",
        "active": True,
        "tags": [{"name": "arenadata-release"}],
    }
    conn = _ProjectConn(response=raw)
    result = api._get_project(conn, project_uuid="P-ABC")  # type: ignore[arg-type]

    assert result is not None
    assert result["uuid"] == "P-ABC"
    assert result["name"] == "adh"
    assert result["version"] == "3.2.1"
    assert conn.calls == [("/api/v1/project/P-ABC", None)]


def test__get_project_returns_none_on_404():
    conn = _ProjectConn(raise_status=404)
    assert api._get_project(conn, project_uuid="missing") is None  # type: ignore[arg-type]


def test__get_project_reraises_non_404():
    conn = _ProjectConn(raise_status=500)
    with pytest.raises(Exception):
        api._get_project(conn, project_uuid="P-ABC")  # type: ignore[arg-type]


def test__get_project_empty_response_is_none():
    """DT can legitimately return an empty body (e.g. null) — treat as miss."""
    conn = _ProjectConn(response=None)
    assert api._get_project(conn, project_uuid="P-ABC") is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# resolve_project (v0.7 — merged lookup_project + get_project)
# ---------------------------------------------------------------------------


def test_resolve_project_by_uuid():
    raw = {"uuid": "P-1", "name": "app", "version": "1.0", "active": True}
    conn = _ProjectConn(response=raw)
    result = api.resolve_project(conn, project_uuid="P-1")  # type: ignore[arg-type]
    assert result is not None
    assert result["uuid"] == "P-1"


def test_resolve_project_by_name_version():
    raw = {"uuid": "P-2", "name": "app", "version": "2.0", "active": True}
    conn = _ProjectConn(response=raw)
    result = api.resolve_project(conn, name="app", version="2.0")  # type: ignore[arg-type]
    assert result is not None
    assert result["uuid"] == "P-2"


def test_resolve_project_uuid_takes_precedence():
    raw = {"uuid": "P-UUID", "name": "ignored", "version": "x", "active": True}
    conn = _ProjectConn(response=raw)
    result = api.resolve_project(conn, project_uuid="P-UUID", name="app", version="1.0")  # type: ignore[arg-type]
    assert result is not None
    assert result["uuid"] == "P-UUID"
    assert conn.calls[0][0] == "/api/v1/project/P-UUID"


def test_resolve_project_no_params_raises():
    conn = _ProjectConn()
    with pytest.raises(DTrackError, match="project_uuid or both name and version"):
        api.resolve_project(conn)  # type: ignore[arg-type]


def test_resolve_project_name_without_version_raises():
    conn = _ProjectConn()
    with pytest.raises(DTrackError, match="project_uuid or both name and version"):
        api.resolve_project(conn, name="app")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# find_vulnerability with explicit source (v0.7 — merged get_vulnerability)
# ---------------------------------------------------------------------------


class _VulnConn:
    def __init__(self, response: Any = None, *, raise_status: int | None = None):
        self._response = response
        self._raise_status = raise_status
        self.paths: list[str] = []

    def get(self, path: str, params: Any = None) -> Any:
        self.paths.append(path)
        if self._raise_status:
            raise DTrackHTTPError(self._raise_status, "err", path)
        return self._response


def test_find_vulnerability_with_source_direct():
    raw = {"uuid": "V-1", "source": "NVD", "vulnId": "CVE-2024-1234", "severity": "HIGH"}
    conn = _VulnConn(response=raw)
    result = api.find_vulnerability(conn, vuln_id="CVE-2024-1234", source="NVD")  # type: ignore[arg-type]
    assert result is not None
    assert result["vuln_id"] == "CVE-2024-1234"
    assert len(conn.paths) == 1
    assert "NVD" in conn.paths[0]


def test_find_vulnerability_without_source_probes():
    raw = {"uuid": "V-2", "source": "NVD", "vulnId": "CVE-2024-5678", "severity": "MEDIUM"}
    conn = _VulnConn(response=raw)
    result = api.find_vulnerability(conn, vuln_id="CVE-2024-5678")  # type: ignore[arg-type]
    assert result is not None
    assert result["vuln_id"] == "CVE-2024-5678"


def test_find_vulnerability_with_source_404_returns_none():
    conn = _VulnConn(raise_status=404)
    result = api.find_vulnerability(conn, vuln_id="CVE-X", source="NVD")  # type: ignore[arg-type]
    assert result is None


# ---------------------------------------------------------------------------
# search_vulnerability (v0.7 — new tool)
# ---------------------------------------------------------------------------


def test_search_vulnerability_not_found(monkeypatch):
    monkeypatch.setattr(api, "find_vulnerability", lambda _c, **kw: None)
    conn = _VulnConn()
    result = api.search_vulnerability(conn, vuln_id="CVE-FAKE")  # type: ignore[arg-type]
    assert result is None


def test_search_vulnerability_finds_projects(monkeypatch):
    vuln = {
        "uuid": "V-1", "source": "NVD", "vuln_id": "CVE-2024-1234",
        "title": "test", "description": "test", "severity": "HIGH",
        "cvss_v3_score": 7.5, "cvss_v3_vector": None,
        "cvss_v4_score": None, "cvss_v4_vector": None, "cvss_v2_score": None,
        "cwes": [], "epss_score": None, "epss_percentile": None,
        "in_kev": False, "published": None, "updated": None,
        "references": [], "aliases": [], "affected_components_count": None,
    }
    monkeypatch.setattr(api, "find_vulnerability", lambda _c, **kw: vuln)

    project_raw = {
        "uuid": "P-1", "name": "app", "version": "1.0",
        "active": True, "metrics": {},
    }
    finding = _finding("V-1", "CVE-2024-1234", _comp("C-1"))
    analysis = {
        "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE",
        "response": None, "details": None, "is_suppressed": False, "comments": [],
    }

    monkeypatch.setattr(api, "_fetch_all_findings", lambda _c, _u, **kw: [finding])
    monkeypatch.setattr(api, "get_analysis", lambda _c, **kw: analysis)

    class _SearchConn:
        def get(self, path, params=None):
            if "/projects" in path:
                return [project_raw]
            return None

    result = api.search_vulnerability(_SearchConn(), vuln_id="CVE-2024-1234")  # type: ignore[arg-type]
    assert result is not None
    assert result["total_projects"] == 1
    assert result["affected_projects"][0]["project"]["name"] == "app"
    assert result["affected_projects"][0]["analyses"][0]["state"] == "NOT_AFFECTED"
