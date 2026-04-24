"""Unit tests for normalize.py driven by real DT 4.14.1 fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dtrack_mcp.normalize import (
    _parse_purl,
    epoch_ms_to_iso,
    extract_cwes,
    extract_references,
    flatten_aliases,
    normalize_component,
    normalize_finding,
    normalize_project,
    normalize_vulnerability,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def project_one() -> dict:
    return json.loads((FIXTURES / "project_one.json").read_text())


@pytest.fixture(scope="module")
def findings_small() -> list[dict]:
    return json.loads((FIXTURES / "findings_small.json").read_text())


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def test_epoch_ms_to_iso_known_value():
    # 1772168272624 ms -> 2026-02-27T07:37:52Z (verified via datetime)
    result = epoch_ms_to_iso(1772168272624)
    assert result is not None
    assert result.endswith("Z")
    assert result.startswith("2026-")


def test_epoch_ms_to_iso_none_and_invalid():
    assert epoch_ms_to_iso(None) is None
    assert epoch_ms_to_iso("") is None
    assert epoch_ms_to_iso("not a number") is None


def test_flatten_aliases_multi_id_object():
    raw = [{"cveId": "CVE-2025-11226", "ghsaId": "GHSA-25qh-j22f-pwp8"}]
    out = flatten_aliases(raw)
    assert out == [
        {"source": "NVD", "vuln_id": "CVE-2025-11226"},
        {"source": "GITHUB", "vuln_id": "GHSA-25qh-j22f-pwp8"},
    ]


def test_flatten_aliases_dedupes_across_objects():
    raw = [
        {"cveId": "CVE-1", "ghsaId": "GHSA-a"},
        {"cveId": "CVE-1", "osvId": "OSV-x"},  # CVE-1 repeats, OSV is new
    ]
    out = flatten_aliases(raw)
    assert len(out) == 3
    ids = [(r["source"], r["vuln_id"]) for r in out]
    assert ("NVD", "CVE-1") in ids
    assert ("GITHUB", "GHSA-a") in ids
    assert ("OSV", "OSV-x") in ids


def test_flatten_aliases_empty_and_malformed():
    assert flatten_aliases(None) == []
    assert flatten_aliases([]) == []
    assert flatten_aliases([{"unknownField": "x"}]) == []
    assert flatten_aliases(["not a dict"]) == []  # type: ignore[list-item]


def test_extract_cwes_merges_single_and_list():
    raw = {
        "cweId": 20,
        "cwes": [{"cweId": 20, "name": "x"}, {"cweId": 79, "name": "y"}],
    }
    assert extract_cwes(raw) == [20, 79]


def test_extract_cwes_handles_missing():
    assert extract_cwes({}) == []


def test_extract_references_pulls_urls_from_markdown():
    raw = {
        "references": (
            "* [https://nvd.nist.gov/vuln/detail/CVE-2024-26308]"
            "(https://nvd.nist.gov/vuln/detail/CVE-2024-26308)\n"
            "* [https://github.com/advisories/GHSA-4265-ccf5-phj5]"
            "(https://github.com/advisories/GHSA-4265-ccf5-phj5)"
        )
    }
    urls = extract_references(raw)
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-26308" in urls
    assert "https://github.com/advisories/GHSA-4265-ccf5-phj5" in urls
    # No duplicates even though the URL appears twice in markdown.
    assert len(urls) == len(set(urls))


def test_extract_references_list_of_objects():
    raw = {"references": [{"url": "https://example.com/a"}]}
    assert extract_references(raw) == ["https://example.com/a"]


def test_extract_references_empty():
    assert extract_references({}) == []


# ---------------------------------------------------------------------------
# Top-level: NormalizedProject
# ---------------------------------------------------------------------------


def test_normalize_project_basic_fields(project_one):
    p = normalize_project(project_one)
    assert p["uuid"] == "164cc78e-e21f-4a1c-93a3-302caaad8e40"
    assert p["name"] == "adh-jmx-exporter"
    assert p["version"] == "0.0.0"
    assert p["classifier"] == "APPLICATION"
    assert p["active"] is True
    assert p["is_latest"] is False


def test_normalize_project_metrics_flattened(project_one):
    m = normalize_project(project_one)["metrics"]
    assert m["vulnerabilities"] == 5
    assert m["high"] == 1
    assert m["medium"] == 3
    assert m["low"] == 1
    assert m["critical"] == 0
    assert m["findings_total"] == 5
    assert m["inherited_risk_score"] == 15.0


def test_audit_ratio_computed_from_metrics():
    from dtrack_mcp.normalize import normalize_project_metrics

    m = normalize_project_metrics(
        {"findingsTotal": 10, "findingsAudited": 3, "findingsUnaudited": 7}
    )
    assert m["audit_ratio"] == 0.3


def test_audit_ratio_is_none_when_total_zero():
    from dtrack_mcp.normalize import normalize_project_metrics

    m = normalize_project_metrics({"findingsTotal": 0, "findingsAudited": 0})
    assert m["audit_ratio"] is None


def test_audit_ratio_fully_audited():
    from dtrack_mcp.normalize import normalize_project_metrics

    m = normalize_project_metrics({"findingsTotal": 7, "findingsAudited": 7})
    assert m["audit_ratio"] == 1.0


def test_normalize_project_timestamps_from_metrics(project_one):
    p = normalize_project(project_one)
    assert p["first_seen"] is not None
    assert p["last_seen"] is not None
    assert p["first_seen"].endswith("Z")


def test_normalize_project_strips_bloat(project_one):
    """Normalized project must NOT carry directDependencies, properties,
    versions, externalReferences, or raw metrics policy counters."""
    p = normalize_project(project_one)
    assert "directDependencies" not in p
    assert "properties" not in p
    assert "policyViolationsFail" not in p["metrics"]
    assert "policyViolationsTotal" not in p["metrics"]


# ---------------------------------------------------------------------------
# Top-level: NormalizedFinding
# ---------------------------------------------------------------------------


def test_normalize_finding_count(findings_small):
    # The /finding endpoint returns per (component, vulnerability) pairs,
    # so the count can exceed metrics.vulnerabilities. Just ensure every
    # raw entry normalizes without error.
    assert len(findings_small) > 0
    normalized = [normalize_finding(f) for f in findings_small]
    assert len(normalized) == len(findings_small)
    for f in normalized:
        assert f["vulnerability"]["vuln_id"]
        assert f["component"]["uuid"]


def test_normalize_finding_first_item(findings_small):
    f = normalize_finding(findings_small[0])
    # component
    assert f["component"]["name"] == "logback-core"
    assert f["component"]["version"] == "1.5.17"
    assert f["component"]["group"] == "ch.qos.logback"
    assert f["component"]["latest_version"] == "1.5.32"
    assert f["component"]["purl"].startswith("pkg:maven/ch.qos.logback/logback-core")
    # vulnerability summary
    v = f["vulnerability"]
    assert v["source"] == "GITHUB"
    assert v["vuln_id"] == "GHSA-25qh-j22f-pwp8"
    assert v["severity"] == "MEDIUM"
    assert v["cvss_v4_score"] == 5.9
    assert v["cvss_v3_score"] is None  # no v3 score in this finding
    assert 20 in v["cwes"]
    assert v["epss_score"] == 0.00058
    assert v["in_kev"] is False
    # aliases flattened: both CVE and GHSA
    alias_ids = {(a["source"], a["vuln_id"]) for a in v["aliases"]}
    assert ("NVD", "CVE-2025-11226") in alias_ids
    assert ("GITHUB", "GHSA-25qh-j22f-pwp8") in alias_ids
    # analysis defaults for unanalyzed finding
    assert f["analysis"]["state"] == "NOT_SET"
    assert f["analysis"]["is_suppressed"] is False
    # attribution timestamp converted
    assert f["attributed_on"] is not None
    assert f["attributed_on"].endswith("Z")


def test_normalize_finding_with_cvss_v3(findings_small):
    """Third finding in fixture has both v3 and v4 scores (commons-compress)."""
    f = normalize_finding(findings_small[2])
    assert f["component"]["name"] == "commons-compress"
    assert f["vulnerability"]["cvss_v3_score"] == 5.5
    assert f["vulnerability"]["cvss_v3_vector"].startswith("CVSS:3.1/")
    assert f["vulnerability"]["cvss_v4_score"] == 6.7


# ---------------------------------------------------------------------------
# Top-level: NormalizedVulnerability (via finding.vulnerability reuse)
# ---------------------------------------------------------------------------


def test_normalize_vulnerability_from_finding_payload(findings_small):
    raw_v = findings_small[0]["vulnerability"]
    v = normalize_vulnerability(raw_v)
    assert v["source"] == "GITHUB"
    assert v["vuln_id"] == "GHSA-25qh-j22f-pwp8"
    assert v["title"].startswith("QOS.CH logback-core")
    assert v["description"] is not None
    assert v["severity"] == "MEDIUM"
    assert v["epss_score"] == 0.00058
    assert v["epss_percentile"] == 0.17741
    assert v["published"] is not None
    assert v["published"].startswith("2025-")
    # references scraped from markdown
    assert any("github.com/advisories" in r for r in v["references"])
    # aliases flattened
    ids = {(a["source"], a["vuln_id"]) for a in v["aliases"]}
    assert ("NVD", "CVE-2025-11226") in ids


# ---------------------------------------------------------------------------
# v0.2: _parse_purl — PURL string decomposition for component matching
# ---------------------------------------------------------------------------


def test_parse_purl_simple_npm() -> None:
    r = _parse_purl("pkg:npm/lodash@4.17.21")
    assert r["purl_type"] == "npm"
    assert r["purl_namespace"] is None
    assert r["purl_name"] == "lodash"
    assert r["purl_version"] == "4.17.21"
    assert r["purl_qualifiers"] == {}


def test_parse_purl_maven_with_namespace() -> None:
    r = _parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0")
    assert r["purl_type"] == "maven"
    assert r["purl_namespace"] == "org.apache.logging.log4j"
    assert r["purl_name"] == "log4j-core"
    assert r["purl_version"] == "2.17.0"


def test_parse_purl_deb_with_distro_qualifier() -> None:
    # DT 4.14 adds distro=... automatically; must land in qualifiers, not name.
    r = _parse_purl("pkg:deb/debian/openssl@1.1.1?distro=bookworm")
    assert r["purl_type"] == "deb"
    assert r["purl_namespace"] == "debian"
    assert r["purl_name"] == "openssl"
    assert r["purl_version"] == "1.1.1"
    assert r["purl_qualifiers"] == {"distro": "bookworm"}


def test_parse_purl_multiple_qualifiers_lowercased_keys() -> None:
    r = _parse_purl("pkg:rpm/fedora/nss@3.x?ARCH=x86_64&distro=fc35")
    assert r["purl_qualifiers"] == {"arch": "x86_64", "distro": "fc35"}


def test_parse_purl_npm_scoped_percent_encoded() -> None:
    # npm scoped packages: namespace is %40scope → @scope after unquote.
    r = _parse_purl("pkg:npm/%40angular/core@15.0.0")
    assert r["purl_type"] == "npm"
    assert r["purl_namespace"] == "@angular"
    assert r["purl_name"] == "core"
    assert r["purl_version"] == "15.0.0"


def test_parse_purl_unscoped_vs_scoped_have_different_match_keys() -> None:
    # Sanity: plain "pkg:npm/core" and "pkg:npm/%40angular/core" must not
    # collapse — component_match_key uses (type, ns, name) and namespace
    # differs (None vs "@angular").
    a = _parse_purl("pkg:npm/core@1.0.0")
    b = _parse_purl("pkg:npm/%40angular/core@15.0.0")
    assert (a["purl_type"], a["purl_namespace"], a["purl_name"]) != (
        b["purl_type"],
        b["purl_namespace"],
        b["purl_name"],
    )


def test_parse_purl_subpath_is_stripped() -> None:
    r = _parse_purl("pkg:golang/github.com/foo/bar@v1.0.0#cmd/main")
    assert r["purl_type"] == "golang"
    assert r["purl_namespace"] == "github.com/foo"
    assert r["purl_name"] == "bar"
    assert r["purl_version"] == "v1.0.0"


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "not-a-purl",
        "pkg:",
        "pkg:maven",  # type only, no name
        "pkg:maven///",  # empty segments
    ],
)
def test_parse_purl_poisoned_inputs_graceful_degrade(bad) -> None:
    r = _parse_purl(bad)
    assert r == {
        "purl_type": None,
        "purl_namespace": None,
        "purl_name": None,
        "purl_version": None,
        "purl_qualifiers": {},
    }


def test_normalize_component_populates_purl_fields() -> None:
    raw = {
        "uuid": "comp-1",
        "name": "openssl",
        "version": "1.1.1",
        "purl": "pkg:deb/debian/openssl@1.1.1?distro=bookworm",
    }
    c = normalize_component(raw)
    assert c["purl"] == "pkg:deb/debian/openssl@1.1.1?distro=bookworm"
    assert c["purl_type"] == "deb"
    assert c["purl_namespace"] == "debian"
    assert c["purl_name"] == "openssl"
    assert c["purl_version"] == "1.1.1"
    assert c["purl_qualifiers"] == {"distro": "bookworm"}


def test_normalize_component_missing_purl_still_valid() -> None:
    c = normalize_component({"uuid": "x", "name": "custom", "version": "1.0"})
    assert c["purl"] is None
    assert c["purl_type"] is None
    assert c["purl_qualifiers"] == {}


# ---------------------------------------------------------------------------
# v0.3 / Stage 4: normalize_finding(include_details=...)
# ---------------------------------------------------------------------------


def test_normalize_finding_details_off_by_default(findings_small) -> None:
    f = normalize_finding(findings_small[0])
    v = f["vulnerability"]
    assert v["title"] is None
    assert v["description"] is None
    assert v["references"] == []


def test_normalize_finding_details_on_populates_fields(findings_small) -> None:
    f = normalize_finding(findings_small[0], include_details=True)
    v = f["vulnerability"]
    assert v["title"] is not None
    assert v["title"].startswith("QOS.CH logback-core")
    assert v["description"] is not None
    assert "logback-core" in v["description"]
    assert len(v["references"]) > 0
    assert all(r.startswith("http") for r in v["references"])
    assert any("github.com/advisories" in r for r in v["references"])


def test_normalize_finding_details_on_empty_vuln_fields() -> None:
    # A finding whose vulnerability lacks title/description/references
    # must still yield the three detail fields as None / [].
    raw = {
        "component": {"uuid": "c1", "name": "x", "version": "1.0"},
        "vulnerability": {
            "uuid": "v1",
            "source": "NVD",
            "vulnId": "CVE-2099-0001",
            "severity": "LOW",
        },
        "analysis": {},
        "attribution": {},
    }
    f = normalize_finding(raw, include_details=True)
    v = f["vulnerability"]
    assert v["title"] is None
    assert v["description"] is None
    assert v["references"] == []


def test_normalize_finding_details_other_fields_unchanged(findings_small) -> None:
    # Toggling include_details must not alter the rest of the summary.
    off = normalize_finding(findings_small[0])["vulnerability"]
    on = normalize_finding(
        findings_small[0], include_details=True
    )["vulnerability"]
    stable_keys = [
        "uuid", "source", "vuln_id", "severity",
        "cvss_v3_score", "cvss_v3_vector", "cvss_v4_score", "cvss_v4_vector",
        "cwes", "epss_score", "in_kev", "aliases",
    ]
    for k in stable_keys:
        assert off[k] == on[k], f"field {k} differs between include_details modes"
