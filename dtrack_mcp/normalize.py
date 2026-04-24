"""Pure functions that convert raw Dependency-Track JSON to normalized shapes.

These functions never touch the network and never mutate input. They are
the single place where DT field names and shapes are translated — any
new field added to a normalized schema must be sourced here.

Shapes reverse-engineered from DT 4.14.1 responses; see
``tests/fixtures/`` for the exact payloads the parsers were written
against.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from .models import (
    AnalysisState,
    FindingAnalysis,
    FindingVulnerabilitySummary,
    NormalizedComponent,
    NormalizedFinding,
    NormalizedProject,
    NormalizedVulnerability,
    ProjectMetrics,
    Severity,
    VulnerabilityRef,
)

# DT alias objects carry multiple id fields at once. Map each field name
# to the canonical DT "source" string for that id namespace.
_ALIAS_FIELD_TO_SOURCE: dict[str, str] = {
    "cveId": "NVD",
    "ghsaId": "GITHUB",
    "osvId": "OSV",
    "snykId": "SNYK",
    "sonatypeId": "SONATYPE",
    "gsdId": "GSD",
    "vulnDbId": "VULNDB",
    "internalId": "INTERNAL",
}

_VALID_SEVERITIES: set[str] = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED"}

_VALID_ANALYSIS_STATES: set[str] = {
    "NOT_SET",
    "IN_TRIAGE",
    "EXPLOITABLE",
    "FALSE_POSITIVE",
    "NOT_AFFECTED",
    "RESOLVED",
}

_URL_RE = re.compile(r"https?://[^\s)\]\"'>]+")


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def epoch_ms_to_iso(value: Any) -> str | None:
    """Convert Dependency-Track epoch-milliseconds to ISO-8601 UTC.

    Returns ``None`` for ``None``, empty, or unparseable input. Never raises.
    """
    if value is None or value == "":
        return None
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return None
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity(value: Any) -> Severity:
    """Coerce a DT severity string to the Severity literal. Unknown → UNASSIGNED."""
    if isinstance(value, str) and value.upper() in _VALID_SEVERITIES:
        return value.upper()  # type: ignore[return-value]
    return "UNASSIGNED"


def _analysis_state(value: Any) -> AnalysisState:
    if isinstance(value, str) and value.upper() in _VALID_ANALYSIS_STATES:
        return value.upper()  # type: ignore[return-value]
    return "NOT_SET"


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    return value or None


def extract_cwes(raw_vuln: dict[str, Any]) -> list[int]:
    """Pull CWE ids out of a vulnerability dict.

    DT sometimes ships both ``cweId`` (single int) and ``cwes`` (list of
    objects). Merge and dedupe, preserving order of first appearance.
    """
    seen: set[int] = set()
    result: list[int] = []
    single = _int_or_none(raw_vuln.get("cweId"))
    if single is not None and single not in seen:
        seen.add(single)
        result.append(single)
    for entry in raw_vuln.get("cwes") or []:
        cid = _int_or_none(entry.get("cweId") if isinstance(entry, dict) else entry)
        if cid is not None and cid not in seen:
            seen.add(cid)
            result.append(cid)
    return result


def extract_references(raw_vuln: dict[str, Any]) -> list[str]:
    """Pull URLs out of DT's ``references`` field.

    DT stores references as a single markdown-ish string of bullet lines.
    We scrape URLs with a regex and dedupe preserving order.
    """
    raw = raw_vuln.get("references")
    if not raw:
        return []
    if isinstance(raw, list):
        # Some DT versions return a list of dicts {"url": ...}; handle both.
        urls: list[str] = []
        for item in raw:
            if isinstance(item, dict):
                u = _str_or_none(item.get("url"))
                if u:
                    urls.append(u)
            elif isinstance(item, str):
                urls.extend(_URL_RE.findall(item))
        return list(dict.fromkeys(urls))
    if isinstance(raw, str):
        return list(dict.fromkeys(_URL_RE.findall(raw)))
    return []


def flatten_aliases(raw_aliases: Any) -> list[VulnerabilityRef]:
    """Flatten DT's grouped alias objects into individual VulnerabilityRefs.

    DT represents aliases as objects like
    ``{"cveId": "CVE-...", "ghsaId": "GHSA-..."}`` — a single object can
    name several identifiers at once. This function fans each one out into
    its own ``{source, vuln_id}`` ref, deduplicating across the whole list.
    """
    if not raw_aliases:
        return []
    seen: set[tuple[str, str]] = set()
    result: list[VulnerabilityRef] = []
    for entry in raw_aliases:
        if not isinstance(entry, dict):
            continue
        for field, source in _ALIAS_FIELD_TO_SOURCE.items():
            vid = entry.get(field)
            if not isinstance(vid, str) or not vid:
                continue
            key = (source, vid)
            if key in seen:
                continue
            seen.add(key)
            result.append({"source": source, "vuln_id": vid})
    return result


# ---------------------------------------------------------------------------
# Top-level normalizers
# ---------------------------------------------------------------------------


def normalize_project(raw: dict[str, Any]) -> NormalizedProject:
    """Convert a raw DT project dict to ``NormalizedProject``.

    Handles both single-project responses (``/project/{uuid}``) and items
    inside list responses (``/project?...``). ``firstOccurrence`` and
    ``lastOccurrence`` live inside ``metrics`` on DT 4.14.
    """
    raw_metrics: dict[str, Any] = raw.get("metrics") or {}
    return NormalizedProject(
        uuid=raw["uuid"],
        name=raw.get("name", ""),
        version=_str_or_none(raw.get("version")),
        classifier=raw.get("classifier", "") or "",
        active=bool(raw.get("active", False)),
        is_latest=bool(raw.get("isLatest", False)),
        first_seen=epoch_ms_to_iso(raw_metrics.get("firstOccurrence")),
        last_seen=epoch_ms_to_iso(raw_metrics.get("lastOccurrence")),
        metrics=normalize_project_metrics(raw_metrics),
    )


def normalize_project_metrics(raw: dict[str, Any]) -> ProjectMetrics:
    findings_total = int(raw.get("findingsTotal", 0) or 0)
    findings_audited = int(raw.get("findingsAudited", 0) or 0)
    audit_ratio = (
        findings_audited / findings_total if findings_total > 0 else None
    )
    return ProjectMetrics(
        vulnerabilities=int(raw.get("vulnerabilities", 0) or 0),
        critical=int(raw.get("critical", 0) or 0),
        high=int(raw.get("high", 0) or 0),
        medium=int(raw.get("medium", 0) or 0),
        low=int(raw.get("low", 0) or 0),
        unassigned=int(raw.get("unassigned", 0) or 0),
        findings_total=findings_total,
        findings_audited=findings_audited,
        findings_unaudited=int(raw.get("findingsUnaudited", 0) or 0),
        inherited_risk_score=float(raw.get("inheritedRiskScore", 0.0) or 0.0),
        audit_ratio=audit_ratio,
    )


def _parse_purl(purl: str | None) -> dict[str, Any]:
    """Parse a purl string into its structural parts.

    Spec: ``pkg:type/namespace/name@version?k1=v1&k2=v2#subpath``. Subpath
    is dropped (not needed for v0.2). On any parse failure all fields are
    ``None`` / empty dict — the caller keeps the original ``purl`` string
    for display.
    """
    blank: dict[str, Any] = {
        "purl_type": None,
        "purl_namespace": None,
        "purl_name": None,
        "purl_version": None,
        "purl_qualifiers": {},
    }
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return blank
    body = purl[4:].split("#", 1)[0]
    qual_str = ""
    if "?" in body:
        body, qual_str = body.split("?", 1)
    if "@" in body:
        path_part, version_raw = body.split("@", 1)
        version: str | None = unquote(version_raw) or None
    else:
        path_part, version = body, None
    segments = [s for s in path_part.split("/") if s]
    if len(segments) < 2:
        return blank
    ptype = segments[0].lower()
    name = unquote(segments[-1])
    namespace: str | None = None
    if len(segments) > 2:
        namespace = unquote("/".join(segments[1:-1]))
    qualifiers: dict[str, str] = {}
    for pair in qual_str.split("&") if qual_str else ():
        if not pair or "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        if k:
            qualifiers[k.lower()] = unquote(v)
    return {
        "purl_type": ptype,
        "purl_namespace": namespace,
        "purl_name": name,
        "purl_version": version,
        "purl_qualifiers": qualifiers,
    }


def normalize_component(raw: dict[str, Any]) -> NormalizedComponent:
    purl = _str_or_none(raw.get("purl"))
    parsed = _parse_purl(purl)
    return NormalizedComponent(
        uuid=raw.get("uuid", ""),
        name=raw.get("name", ""),
        version=_str_or_none(raw.get("version")),
        group=_str_or_none(raw.get("group")),
        purl=purl,
        purl_type=parsed["purl_type"],
        purl_namespace=parsed["purl_namespace"],
        purl_name=parsed["purl_name"],
        purl_version=parsed["purl_version"],
        purl_qualifiers=parsed["purl_qualifiers"],
        latest_version=_str_or_none(raw.get("latestVersion")),
    )


def normalize_finding(
    raw: dict[str, Any], *, include_details: bool = False
) -> NormalizedFinding:
    """Convert one item from ``/finding/project/{uuid}`` to ``NormalizedFinding``.

    When ``include_details=True`` the embedded summary carries ``title``,
    ``description``, and ``references`` sourced from the same raw payload
    (no extra HTTP). When ``False`` (default) those three fields are
    populated with ``None`` / ``[]`` to keep the list payload compact —
    see SPEC §12 for the size rationale.
    """
    raw_vuln: dict[str, Any] = raw.get("vulnerability") or {}
    raw_comp: dict[str, Any] = raw.get("component") or {}
    raw_analysis: dict[str, Any] = raw.get("analysis") or {}
    raw_attr: dict[str, Any] = raw.get("attribution") or {}

    if include_details:
        title = _str_or_none(raw_vuln.get("title"))
        description = _str_or_none(raw_vuln.get("description"))
        references = extract_references(raw_vuln)
    else:
        title = None
        description = None
        references = []

    vuln_summary = FindingVulnerabilitySummary(
        uuid=raw_vuln.get("uuid", ""),
        source=raw_vuln.get("source", "") or "",
        vuln_id=raw_vuln.get("vulnId", "") or "",
        severity=_severity(raw_vuln.get("severity")),
        cvss_v3_score=_float_or_none(raw_vuln.get("cvssV3BaseScore")),
        cvss_v3_vector=_str_or_none(raw_vuln.get("cvssV3Vector")),
        cvss_v4_score=_float_or_none(raw_vuln.get("cvssV4Score")),
        cvss_v4_vector=_str_or_none(raw_vuln.get("cvssV4Vector")),
        cwes=extract_cwes(raw_vuln),
        epss_score=_float_or_none(raw_vuln.get("epssScore")),
        in_kev=bool(raw_vuln.get("knownExploited", False)),
        aliases=flatten_aliases(raw_vuln.get("aliases")),
        title=title,
        description=description,
        references=references,
    )

    analysis = FindingAnalysis(
        state=_analysis_state(raw_analysis.get("state")),
        justification=_str_or_none(raw_analysis.get("justification")),
        is_suppressed=bool(raw_analysis.get("isSuppressed", False)),
    )

    return NormalizedFinding(
        vulnerability=vuln_summary,
        component=normalize_component(raw_comp),
        analysis=analysis,
        attributed_on=epoch_ms_to_iso(raw_attr.get("attributedOn")),
    )


def normalize_vulnerability(raw: dict[str, Any]) -> NormalizedVulnerability:
    """Convert a raw DT vulnerability dict to ``NormalizedVulnerability``.

    Works for both ``/vulnerability/source/{s}/vuln/{id}`` responses and
    the nested ``finding.vulnerability`` object, since DT uses the same
    field names in both contexts.
    """
    return NormalizedVulnerability(
        uuid=raw.get("uuid", ""),
        source=raw.get("source", "") or "",
        vuln_id=raw.get("vulnId", "") or "",
        title=_str_or_none(raw.get("title")),
        description=_str_or_none(raw.get("description")),
        severity=_severity(raw.get("severity")),
        cvss_v3_score=_float_or_none(raw.get("cvssV3BaseScore")),
        cvss_v3_vector=_str_or_none(raw.get("cvssV3Vector")),
        cvss_v4_score=_float_or_none(raw.get("cvssV4Score")),
        cvss_v4_vector=_str_or_none(raw.get("cvssV4Vector")),
        cvss_v2_score=_float_or_none(raw.get("cvssV2BaseScore")),
        cwes=extract_cwes(raw),
        epss_score=_float_or_none(raw.get("epssScore")),
        epss_percentile=_float_or_none(raw.get("epssPercentile")),
        in_kev=bool(raw.get("knownExploited", False)),
        published=epoch_ms_to_iso(raw.get("published")),
        updated=epoch_ms_to_iso(raw.get("updated")),
        references=extract_references(raw),
        aliases=flatten_aliases(raw.get("aliases")),
        affected_components_count=_int_or_none(raw.get("affectedProjectCount")),
    )
