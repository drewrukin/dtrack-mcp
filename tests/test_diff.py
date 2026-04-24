"""Unit tests for ``diff_findings`` — synthetic normalized findings.

The diff algorithm operates on already-normalized findings; we bypass the
HTTP layer by monkeypatching ``_fetch_all_findings`` so tests speak the
same TypedDict shapes the production code does, without carting around
fixture JSON.
"""

from __future__ import annotations

from typing import Any

from dtrack_mcp import api
from dtrack_mcp.models import NormalizedComponent, NormalizedFinding


def _comp(
    uuid: str,
    name: str,
    version: str | None = "1.0",
    *,
    purl_type: str | None = None,
    purl_namespace: str | None = None,
    purl_name: str | None = None,
    purl_version: str | None = None,
    purl: str | None = None,
    qualifiers: dict[str, str] | None = None,
) -> NormalizedComponent:
    return {
        "uuid": uuid,
        "name": name,
        "version": version,
        "group": None,
        "purl": purl,
        "purl_type": purl_type or ("npm" if name else None),
        "purl_namespace": purl_namespace,
        "purl_name": purl_name or name,
        "purl_version": purl_version or version,
        "purl_qualifiers": qualifiers or {},
        "latest_version": None,
    }


def _finding(
    vuln_id: str,
    component: NormalizedComponent,
    *,
    source: str = "NVD",
    aliases: list[tuple[str, str]] | None = None,
    state: str = "NOT_SET",
    vuln_uuid: str | None = None,
) -> NormalizedFinding:
    return {
        "vulnerability": {
            "uuid": vuln_uuid or f"v-{source}-{vuln_id}",
            "source": source,
            "vuln_id": vuln_id,
            "severity": "HIGH",
            "cvss_v3_score": 7.5,
            "cvss_v3_vector": None,
            "cvss_v4_score": None,
            "cvss_v4_vector": None,
            "cwes": [],
            "epss_score": None,
            "in_kev": False,
            "aliases": [{"source": s, "vuln_id": v} for s, v in (aliases or [])],
        },
        "component": component,
        "analysis": {
            "state": state,  # type: ignore[typeddict-item]
            "justification": None,
            "is_suppressed": False,
        },
        "attributed_on": None,
    }


class _FakeConn:
    """Only project metadata passes through .get(); findings are patched."""

    def __init__(self, projects: dict[str, dict[str, Any]]) -> None:
        self.projects = projects
        self.analysis_calls: list[tuple[str, str, str]] = []

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        # /api/v1/project/{uuid}
        for uuid, body in self.projects.items():
            if path == f"/api/v1/project/{uuid}":
                return body
        if path.startswith("/api/v1/analysis"):
            return None
        return None


def _install_fake_findings(
    monkeypatch, source: list[NormalizedFinding], target: list[NormalizedFinding]
) -> None:
    def fake_fetch(conn, project_uuid, *, suppressed):
        if project_uuid == "S":
            return source
        if project_uuid == "T":
            return target
        return []

    monkeypatch.setattr(api, "_fetch_all_findings", fake_fetch)


def _fake_projects() -> dict[str, dict[str, Any]]:
    return {
        "S": {"uuid": "S", "name": "demo", "version": "1.0",
              "classifier": "APPLICATION", "active": True, "metrics": {}},
        "T": {"uuid": "T", "name": "demo", "version": "2.0",
              "classifier": "APPLICATION", "active": True, "metrics": {}},
    }


# ---------------------------------------------------------------------------
# Basic classification
# ---------------------------------------------------------------------------


def test_exact_purl_match_classified_as_carried(monkeypatch):
    purl = "pkg:npm/lodash@1.0"
    c_src = _comp("c1", "lodash", "1.0", purl_type="npm", purl_name="lodash",
                  purl_version="1.0", purl=purl)
    c_tgt = _comp("c2", "lodash", "1.0", purl_type="npm", purl_name="lodash",
                  purl_version="1.0", purl=purl)
    src = [_finding("CVE-1", c_src, state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", c_tgt)]
    _install_fake_findings(monkeypatch, src, tgt)

    conn = _FakeConn(_fake_projects())
    result = api.diff_findings(
        conn, source_project_uuid="S", target_project_uuid="T",
        include_analysis=False,
    )
    assert result["stats"] == {"carried": 1, "updated_component": 0, "new": 0, "gone": 0}
    assert result["carried"][0]["match_reason"] == "exact_purl"


def test_updated_component_same_name_diff_version(monkeypatch):
    c_src = _comp("c1", "lodash", "1.0", purl="pkg:npm/lodash@1.0")
    c_tgt = _comp("c2", "lodash", "2.0", purl="pkg:npm/lodash@2.0")
    src = [_finding("CVE-1", c_src, state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", c_tgt)]
    _install_fake_findings(monkeypatch, src, tgt)

    result = api.diff_findings(
        _FakeConn(_fake_projects()),
        source_project_uuid="S", target_project_uuid="T",
        include_analysis=False,
    )
    assert result["stats"]["updated_component"] == 1
    m = result["updated_component"][0]
    assert m["match_reason"] == "same_component_diff_version"
    assert m["component_version_from"] == "1.0"
    assert m["component_version_to"] == "2.0"


def test_new_finding_when_no_source_match(monkeypatch):
    tgt = [_finding("CVE-NEW", _comp("c2", "newlib", "1.0"))]
    _install_fake_findings(monkeypatch, [], tgt)

    result = api.diff_findings(
        _FakeConn(_fake_projects()),
        source_project_uuid="S", target_project_uuid="T",
        include_analysis=False,
    )
    assert result["stats"]["new"] == 1
    assert result["new"][0]["vulnerability"]["vuln_id"] == "CVE-NEW"


def test_gone_vuln_fixed_vs_component_removed(monkeypatch):
    # libA still present in target (vuln_fixed), libB gone entirely
    c_a_src = _comp("c1", "libA", "1.0")
    c_a_tgt = _comp("c2", "libA", "1.0")
    c_b_src = _comp("c3", "libB", "1.0")
    src = [
        _finding("CVE-1", c_a_src, state="NOT_AFFECTED"),
        _finding("CVE-2", c_b_src, state="NOT_AFFECTED"),
    ]
    # Target has libA but not CVE-1 (fixed) and no libB at all
    tgt = [_finding("CVE-OTHER", c_a_tgt)]
    _install_fake_findings(monkeypatch, src, tgt)

    result = api.diff_findings(
        _FakeConn(_fake_projects()),
        source_project_uuid="S", target_project_uuid="T",
        include_analysis=False,
    )
    reasons = {g["source_finding"]["vulnerability"]["vuln_id"]: g["reason"]
               for g in result["gone"]}
    assert reasons == {"CVE-1": "vuln_fixed", "CVE-2": "component_removed"}


# ---------------------------------------------------------------------------
# Alias-based matching
# ---------------------------------------------------------------------------


def test_exact_alias_match_when_vuln_ids_differ(monkeypatch):
    """Source has GHSA, target has CVE, same component+version → carried."""
    c = _comp("c1", "libfoo", "1.0", purl="pkg:npm/libfoo@1.0")
    src = [_finding("GHSA-aaa", c, source="GITHUB",
                    aliases=[("NVD", "CVE-9")],
                    state="FALSE_POSITIVE")]
    tgt = [_finding("CVE-9", _comp("c2", "libfoo", "1.0", purl="pkg:npm/libfoo@1.0"),
                    aliases=[("GITHUB", "GHSA-aaa")])]
    _install_fake_findings(monkeypatch, src, tgt)

    result = api.diff_findings(
        _FakeConn(_fake_projects()),
        source_project_uuid="S", target_project_uuid="T",
        include_analysis=False,
    )
    assert result["stats"]["carried"] == 1
    # Same version → exact_alias (purls differ only in vuln_id domain; here
    # purls match so it'd be exact_purl — tighten by differing purl below).


def test_exact_alias_when_purls_differ_but_component_matches(monkeypatch):
    c_src = _comp("c1", "libfoo", "1.0", purl="pkg:deb/debian/libfoo@1.0")
    c_tgt = _comp("c2", "libfoo", "1.0",
                  purl="pkg:deb/debian/libfoo@1.0?distro=bookworm",
                  qualifiers={"distro": "bookworm"})
    c_tgt["purl_type"] = "deb"
    c_tgt["purl_namespace"] = "debian"
    c_src["purl_type"] = "deb"
    c_src["purl_namespace"] = "debian"
    src = [_finding("CVE-1", c_src, state="NOT_AFFECTED")]
    tgt = [_finding("CVE-1", c_tgt)]
    _install_fake_findings(monkeypatch, src, tgt)

    result = api.diff_findings(
        _FakeConn(_fake_projects()),
        source_project_uuid="S", target_project_uuid="T",
        include_analysis=False,
    )
    # DT 4.14 distro qualifier change: different purls, same comp_match_key,
    # same version → exact_alias (not exact_purl).
    assert result["stats"]["carried"] == 1
    assert result["carried"][0]["match_reason"] == "exact_alias"


# ---------------------------------------------------------------------------
# Collision warnings
# ---------------------------------------------------------------------------


def test_collision_warning_when_same_comp_key_has_two_distinct_purls(monkeypatch):
    """Multi-arch openssl: amd64 and arm64 collapse to same comp_match_key."""
    c_amd = _comp("c1", "openssl", "1.1.1",
                  purl="pkg:deb/debian/openssl@1.1.1?arch=amd64",
                  purl_type="deb", purl_namespace="debian")
    c_arm = _comp("c2", "openssl", "1.1.1",
                  purl="pkg:deb/debian/openssl@1.1.1?arch=arm64",
                  purl_type="deb", purl_namespace="debian")
    src = [
        _finding("CVE-1", c_amd, state="NOT_AFFECTED", vuln_uuid="v1"),
        _finding("CVE-1", c_arm, state="NOT_AFFECTED", vuln_uuid="v2"),
    ]
    tgt = [_finding("CVE-1", _comp("c3", "openssl", "1.1.1",
                                   purl="pkg:deb/debian/openssl@1.1.1?arch=amd64",
                                   purl_type="deb", purl_namespace="debian"))]
    _install_fake_findings(monkeypatch, src, tgt)

    result = api.diff_findings(
        _FakeConn(_fake_projects()),
        source_project_uuid="S", target_project_uuid="T",
        include_analysis=False,
    )
    assert result["warnings"], "expected at least one collision warning"
    assert "openssl" in result["warnings"][0]
    assert "arch=amd64" in result["warnings"][0] or "arch=arm64" in result["warnings"][0]


# ---------------------------------------------------------------------------
# Split-brain: same vuln on direct and transitive dependency
# ---------------------------------------------------------------------------


def test_split_brain_same_vuln_on_two_components_carries_both(monkeypatch):
    """Same CVE on two distinct components (direct + transitive) in source
    and target. Both target findings should match their own component."""
    c_direct_s = _comp("cs1", "libA", "1.0", purl="pkg:npm/libA@1.0")
    c_trans_s = _comp("cs2", "libB", "1.0", purl="pkg:npm/libB@1.0")
    c_direct_t = _comp("ct1", "libA", "1.0", purl="pkg:npm/libA@1.0")
    c_trans_t = _comp("ct2", "libB", "1.0", purl="pkg:npm/libB@1.0")
    src = [
        _finding("CVE-1", c_direct_s, state="NOT_AFFECTED", vuln_uuid="vA"),
        _finding("CVE-1", c_trans_s, state="FALSE_POSITIVE", vuln_uuid="vB"),
    ]
    tgt = [
        _finding("CVE-1", c_direct_t, vuln_uuid="vAt"),
        _finding("CVE-1", c_trans_t, vuln_uuid="vBt"),
    ]
    _install_fake_findings(monkeypatch, src, tgt)

    result = api.diff_findings(
        _FakeConn(_fake_projects()),
        source_project_uuid="S", target_project_uuid="T",
        include_analysis=False,
    )
    assert result["stats"] == {"carried": 2, "updated_component": 0, "new": 0, "gone": 0}
    assert result["warnings"] == []  # distinct components, distinct comp_keys
