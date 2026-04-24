"""Unit tests for alias.py union-find grouping."""

from __future__ import annotations

from typing import Any

from dtrack_mcp.alias import (
    canonical_ref,
    component_match_key,
    group_findings_by_alias,
    vuln_match_keys,
)
from dtrack_mcp.models import NormalizedComponent, NormalizedFinding


def _finding(
    source: str,
    vuln_id: str,
    aliases: list[tuple[str, str]] | None = None,
    component: str = "libfoo",
    cvss_v3: float | None = None,
    cvss_v4: float | None = None,
) -> NormalizedFinding:
    """Build a minimal NormalizedFinding for tests."""
    return {
        "vulnerability": {
            "uuid": f"uuid-{source}-{vuln_id}",
            "source": source,
            "vuln_id": vuln_id,
            "severity": "HIGH",
            "cvss_v3_score": cvss_v3,
            "cvss_v3_vector": None,
            "cvss_v4_score": cvss_v4,
            "cvss_v4_vector": None,
            "cwes": [],
            "epss_score": None,
            "in_kev": False,
            "aliases": [{"source": s, "vuln_id": v} for s, v in (aliases or [])],
        },
        "component": {
            "uuid": f"comp-{component}",
            "name": component,
            "version": "1.0",
            "group": None,
            "purl": None,
            "latest_version": None,
        },
        "analysis": {
            "state": "NOT_SET",
            "justification": None,
            "is_suppressed": False,
        },
        "attributed_on": None,
    }


# ---------------------------------------------------------------------------
# canonical_ref
# ---------------------------------------------------------------------------


def test_canonical_ref_prefers_nvd():
    refs: list[Any] = [
        {"source": "GITHUB", "vuln_id": "GHSA-xxxx"},
        {"source": "NVD", "vuln_id": "CVE-2024-1234"},
        {"source": "OSV", "vuln_id": "OSV-abc"},
    ]
    assert canonical_ref(refs) == {"source": "NVD", "vuln_id": "CVE-2024-1234"}


def test_canonical_ref_fallback_to_github_when_no_cve():
    refs: list[Any] = [
        {"source": "OSV", "vuln_id": "OSV-abc"},
        {"source": "GITHUB", "vuln_id": "GHSA-yyy"},
    ]
    assert canonical_ref(refs)["source"] == "GITHUB"


def test_canonical_ref_unknown_source_sorts_last():
    refs: list[Any] = [
        {"source": "WEIRD", "vuln_id": "W-1"},
        {"source": "SNYK", "vuln_id": "SNYK-1"},
    ]
    assert canonical_ref(refs)["source"] == "SNYK"


# ---------------------------------------------------------------------------
# group_findings_by_alias — direct pairs
# ---------------------------------------------------------------------------


def test_single_finding_no_aliases_one_group():
    findings = [_finding("GITHUB", "GHSA-1", cvss_v3=5.0)]
    groups = group_findings_by_alias(findings)
    assert len(groups) == 1
    g = groups[0]
    assert g["canonical_id"] == {"source": "GITHUB", "vuln_id": "GHSA-1"}
    assert len(g["findings"]) == 1
    assert g["merge_reason"] == []  # no edges, nothing to log


def test_direct_pair_cve_ghsa_merges():
    """CVE and GHSA findings linked via aliases → one group, CVE canonical."""
    findings = [
        _finding("NVD", "CVE-2024-1", aliases=[("GITHUB", "GHSA-a")], cvss_v3=7.5),
        _finding("GITHUB", "GHSA-a", aliases=[("NVD", "CVE-2024-1")], cvss_v3=7.5),
    ]
    groups = group_findings_by_alias(findings)
    assert len(groups) == 1
    g = groups[0]
    assert g["canonical_id"] == {"source": "NVD", "vuln_id": "CVE-2024-1"}
    assert len(g["findings"]) == 2
    assert len(g["aliases"]) == 2
    assert g["merge_reason"]  # at least one edge logged


# ---------------------------------------------------------------------------
# Transitive closure
# ---------------------------------------------------------------------------


def test_transitive_chain_abc_merges():
    """A↔B, B↔C → {A,B,C} one cluster even though A and C are not direct."""
    findings = [
        _finding("NVD", "CVE-1", aliases=[("GITHUB", "GHSA-B")]),
        _finding("GITHUB", "GHSA-B", aliases=[("OSV", "OSV-C")]),
        _finding("OSV", "OSV-C", aliases=[]),
    ]
    groups = group_findings_by_alias(findings)
    assert len(groups) == 1
    g = groups[0]
    assert g["canonical_id"]["vuln_id"] == "CVE-1"
    assert len(g["findings"]) == 3
    assert {a["vuln_id"] for a in g["aliases"]} == {"CVE-1", "GHSA-B", "OSV-C"}
    # Both chain edges should be in the trace.
    reason = " ".join(g["merge_reason"])
    assert "CVE-1" in reason and "GHSA-B" in reason and "OSV-C" in reason


def test_unrelated_findings_separate_groups():
    findings = [
        _finding("NVD", "CVE-1", cvss_v3=7.0),
        _finding("NVD", "CVE-2", cvss_v3=9.0),
        _finding("NVD", "CVE-3", cvss_v3=5.0),
    ]
    groups = group_findings_by_alias(findings)
    assert len(groups) == 3
    # Sorted by max CVSS desc: CVE-2 (9) > CVE-1 (7) > CVE-3 (5).
    assert [g["canonical_id"]["vuln_id"] for g in groups] == ["CVE-2", "CVE-1", "CVE-3"]


def test_same_vuln_two_components_single_group():
    """Same (source, vuln_id) on two components → one cluster, two findings."""
    findings = [
        _finding("NVD", "CVE-X", component="libfoo"),
        _finding("NVD", "CVE-X", component="libbar"),
    ]
    groups = group_findings_by_alias(findings)
    assert len(groups) == 1
    assert len(groups[0]["findings"]) == 2
    components = {f["component"]["name"] for f in groups[0]["findings"]}
    assert components == {"libfoo", "libbar"}


# ---------------------------------------------------------------------------
# Edge: alias references a vuln not present in project
# ---------------------------------------------------------------------------


def test_alias_to_absent_vuln_still_widens_cluster_names():
    """CVE-1 says it's aliased to GHSA-ghost, but GHSA-ghost has no finding.

    The cluster's ``aliases`` list should still contain GHSA-ghost (it's a
    real alias from DT data), but only CVE-1's finding is attached.
    """
    findings = [_finding("NVD", "CVE-1", aliases=[("GITHUB", "GHSA-ghost")])]
    groups = group_findings_by_alias(findings)
    assert len(groups) == 1
    g = groups[0]
    alias_ids = {a["vuln_id"] for a in g["aliases"]}
    assert "CVE-1" in alias_ids
    assert "GHSA-ghost" in alias_ids
    assert len(g["findings"]) == 1


# ---------------------------------------------------------------------------
# Sort order
# ---------------------------------------------------------------------------


def test_groups_sorted_by_max_cvss_across_v3_and_v4():
    findings = [
        _finding("NVD", "CVE-low", cvss_v3=3.0),
        _finding("NVD", "CVE-high-v4", cvss_v4=9.8),  # higher via v4
        _finding("NVD", "CVE-mid", cvss_v3=6.0),
    ]
    groups = group_findings_by_alias(findings)
    assert [g["canonical_id"]["vuln_id"] for g in groups] == [
        "CVE-high-v4",
        "CVE-mid",
        "CVE-low",
    ]


# ---------------------------------------------------------------------------
# component_match_key
# ---------------------------------------------------------------------------


def _comp(
    name: str = "libfoo",
    purl_type: str | None = None,
    purl_namespace: str | None = None,
    purl_name: str | None = None,
    purl_version: str | None = None,
    purl_qualifiers: dict[str, str] | None = None,
) -> NormalizedComponent:
    return {
        "uuid": "u",
        "name": name,
        "version": purl_version,
        "group": None,
        "purl": None,
        "purl_type": purl_type,
        "purl_namespace": purl_namespace,
        "purl_name": purl_name,
        "purl_version": purl_version,
        "purl_qualifiers": purl_qualifiers or {},
        "latest_version": None,
    }


def test_component_match_key_drops_version_and_qualifiers():
    a = _comp(purl_type="deb", purl_namespace="debian", purl_name="openssl",
             purl_version="1.1.1", purl_qualifiers={"distro": "bookworm"})
    b = _comp(purl_type="deb", purl_namespace="debian", purl_name="openssl",
             purl_version="3.0.0", purl_qualifiers={"distro": "trixie", "arch": "amd64"})
    assert component_match_key(a) == component_match_key(b)
    assert component_match_key(a) == ("deb", "debian", "openssl")


def test_component_match_key_none_namespace_is_empty_string():
    c = _comp(purl_type="npm", purl_namespace=None, purl_name="lodash")
    assert component_match_key(c) == ("npm", "", "lodash")


def test_component_match_key_falls_back_to_name_when_no_purl():
    c = _comp(name="legacy-lib", purl_type=None, purl_name=None)
    assert component_match_key(c) == ("", "", "legacy-lib")


def test_component_match_key_scoped_npm_distinct_from_unscoped():
    scoped = _comp(purl_type="npm", purl_namespace="@angular", purl_name="core")
    unscoped = _comp(purl_type="npm", purl_namespace=None, purl_name="core")
    assert component_match_key(scoped) != component_match_key(unscoped)


# ---------------------------------------------------------------------------
# vuln_match_keys
# ---------------------------------------------------------------------------


def test_vuln_match_keys_primary_plus_aliases():
    vuln = {
        "source": "NVD",
        "vuln_id": "CVE-2024-1",
        "aliases": [
            {"source": "GITHUB", "vuln_id": "GHSA-a"},
            {"source": "OSV", "vuln_id": "OSV-b"},
        ],
    }
    assert vuln_match_keys(vuln) == {
        ("NVD", "CVE-2024-1"),
        ("GITHUB", "GHSA-a"),
        ("OSV", "OSV-b"),
    }


def test_vuln_match_keys_no_aliases_single_key():
    vuln = {"source": "NVD", "vuln_id": "CVE-2024-2", "aliases": []}
    assert vuln_match_keys(vuln) == {("NVD", "CVE-2024-2")}


def test_vuln_match_keys_missing_aliases_field_treated_as_empty():
    vuln = {"source": "NVD", "vuln_id": "CVE-X"}
    assert vuln_match_keys(vuln) == {("NVD", "CVE-X")}


def test_vuln_match_keys_overlap_detects_cross_alias_matches():
    """Two vulns sharing any alias should yield overlapping key sets."""
    a = {
        "source": "NVD",
        "vuln_id": "CVE-1",
        "aliases": [{"source": "GITHUB", "vuln_id": "GHSA-x"}],
    }
    b = {
        "source": "GITHUB",
        "vuln_id": "GHSA-x",
        "aliases": [{"source": "NVD", "vuln_id": "CVE-1"}],
    }
    assert vuln_match_keys(a) & vuln_match_keys(b)
