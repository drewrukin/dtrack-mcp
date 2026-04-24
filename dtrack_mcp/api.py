"""High-level functions on top of :class:`Connection`.

Every function here is what an MCP tool will ultimately call. The tool
layer (``server.py``) only does argument validation and exception
translation — the real work lives here, so it can be unit-tested and
reused from plain Python scripts.

**Read-mostly.** Everything except :func:`set_analysis` issues only GET
requests. :func:`set_analysis` is the single write path; it goes through
``Connection.put_json`` which the connection-layer guard restricts to
``PUT /api/v1/analysis``. See ``feedback_dtrack_readonly.md``.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import time
from typing import Any

from .alias import component_match_key, group_findings_by_alias as _group_by_alias
from .alias import vuln_match_keys as _alias_keys_for
from .connection import Connection, DTrackAuthError, DTrackError, DTrackHTTPError
from .models import (
    AliasGroup,
    BomUploadResult,
    BroadcastResult,
    BroadcastSummary,
    BroadcastTargetResult,
    CarriedMatch,
    CarryOverItemResult,
    CarryOverResult,
    DiffResult,
    DiffStats,
    GoneMatch,
    MatchReason,
    NormalizedAnalysis,
    NormalizedComponent,
    NormalizedFinding,
    NormalizedProject,
    NormalizedVulnerability,
    ProjectVersionsResult,
    UpdatedMatch,
    VulnerabilityRef,
)
from .normalize import (
    epoch_ms_to_iso,
    normalize_finding,
    normalize_project,
    normalize_vulnerability,
)

logger = logging.getLogger(__name__)

# Fixed cap on how many finding entries we will ask DT for. Applied before
# pagination to keep memory bounded on pathological projects.
_MAX_PAGE_SIZE = 500

# Sources we probe when the caller doesn't know which namespace a vuln id
# lives in. Order matters: more common sources first.
_KNOWN_SOURCES: list[str] = [
    "NVD",
    "GITHUB",
    "OSV",
    "SNYK",
    "SONATYPE",
    "VULNDB",
    "INTERNAL",
]


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


def list_projects(
    conn: Connection,
    *,
    name_filter: str | None = None,
    active_only: bool = True,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """List projects with optional substring filter on name.

    Returns ``{"total", "page", "page_size", "items": [NormalizedProject]}``.
    """
    page = max(1, page)
    page_size = _clamp_page_size(page_size, default=50)
    params: dict[str, Any] = {"pageNumber": page, "pageSize": page_size}
    if name_filter:
        # DT 'name' param is an exact match; 'searchText' is the substring filter.
        params["searchText"] = name_filter
    if active_only:
        params["excludeInactive"] = "true"
    raw = conn.get("/api/v1/project", params=params) or []
    items = [normalize_project(p) for p in raw if isinstance(p, dict)]
    return {
        "total": len(items),
        "page": page,
        "page_size": page_size,
        "items": items,
    }


def resolve_project(
    conn: Connection,
    *,
    project_uuid: str | None = None,
    name: str | None = None,
    version: str | None = None,
) -> NormalizedProject | None:
    """Resolve a project by UUID or by exact (name, version).

    At least one lookup path must be provided: either ``project_uuid``
    or both ``name`` and ``version``. When ``project_uuid`` is given it
    takes precedence. Returns None when nothing matches.
    """
    if project_uuid:
        return _get_project(conn, project_uuid=project_uuid)
    if name and version:
        return _lookup_project(conn, name=name, version=version)
    raise DTrackError(
        "resolve_project requires either project_uuid or both name and version"
    )


def _lookup_project(
    conn: Connection, *, name: str, version: str
) -> NormalizedProject | None:
    try:
        raw = conn.get(
            "/api/v1/project/lookup",
            params={"name": name, "version": version},
        )
    except DTrackHTTPError as e:
        if e.status_code == 404:
            return None
        raise
    if not raw:
        return None
    return normalize_project(raw)


def _get_project(
    conn: Connection, *, project_uuid: str
) -> NormalizedProject | None:
    try:
        raw = conn.get(f"/api/v1/project/{project_uuid}")
    except DTrackHTTPError as e:
        if e.status_code in (400, 404):
            return None
        raise
    if not raw:
        return None
    return normalize_project(raw)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def list_findings(
    conn: Connection,
    *,
    project_uuid: str,
    suppressed: bool = False,
    analysis_states: list[str] | None = None,
    severities: list[str] | None = None,
    page: int = 1,
    page_size: int = 100,
    include_details: bool = False,
) -> dict[str, Any]:
    """Return normalized findings for a project with client-side filters.

    All filters are applied to the full finding set returned by DT, in
    this order:
      1. ``suppressed`` — keep only suppressed/unsuppressed per flag;
      2. ``analysis_states`` — whitelist of analysis state strings;
      3. ``severities`` — whitelist of severity strings.

    Pagination is applied after filtering. ``total`` reflects the
    post-filter count.

    ``include_details`` (v0.3): when True, every finding's vulnerability
    summary carries ``title``, ``description``, and ``references`` so an
    LLM can draft a verdict in a single call. Off by default because
    descriptions can be 2–4 KB apiece.
    """
    findings = _fetch_all_findings(
        conn, project_uuid, suppressed=suppressed, include_details=include_details
    )
    filtered = _apply_finding_filters(
        findings,
        analysis_states=analysis_states,
        severities=severities,
    )
    page, page_size = _clamp_pagination(page, page_size, default=100)
    start = (page - 1) * page_size
    items = filtered[start : start + page_size]
    return {
        "total": len(filtered),
        "page": page,
        "page_size": page_size,
        "items": items,
    }


def _fetch_all_findings(
    conn: Connection,
    project_uuid: str,
    *,
    suppressed: bool,
    include_details: bool = False,
) -> list[NormalizedFinding]:
    """Pull the full findings list for a project and normalize it.

    DT's ``/finding/project/{uuid}`` returns the entire set in one shot
    for Stage 1; we accept that and don't chunk. The ``suppressed`` query
    param controls whether suppressed findings are included.
    ``include_details`` is forwarded to ``normalize_finding`` to populate
    the optional ``title``/``description``/``references`` fields.
    """
    params = {"suppressed": "true" if suppressed else "false"}
    raw = conn.get(
        f"/api/v1/finding/project/{project_uuid}", params=params
    ) or []
    return [
        normalize_finding(f, include_details=include_details)
        for f in raw
        if isinstance(f, dict)
    ]


def _apply_finding_filters(
    findings: list[NormalizedFinding],
    *,
    analysis_states: list[str] | None,
    severities: list[str] | None,
) -> list[NormalizedFinding]:
    if analysis_states:
        wanted_states = {s.upper() for s in analysis_states}
        findings = [
            f for f in findings if f["analysis"]["state"] in wanted_states
        ]
    if severities:
        wanted_sev = {s.upper() for s in severities}
        findings = [
            f for f in findings if f["vulnerability"]["severity"] in wanted_sev
        ]
    return findings


# ---------------------------------------------------------------------------
# Alias grouping
# ---------------------------------------------------------------------------


def group_findings_by_alias(
    conn: Connection,
    *,
    project_uuid: str,
    suppressed: bool = False,
    analysis_states: list[str] | None = None,
    severities: list[str] | None = None,
    page: int = 1,
    page_size: int = 100,
    include_details: bool = False,
) -> dict[str, Any]:
    """Group a project's findings by transitive alias closure.

    Accepts the same filters as :func:`list_findings`; pagination is
    applied to the resulting groups, not to the findings inside them
    (groups always ship complete — see SPEC §7.6). ``include_details``
    (v0.3) works like in :func:`list_findings`; note that the same
    description text will appear on every finding inside a group, since
    they share a vulnerability cluster.
    """
    findings = _fetch_all_findings(
        conn, project_uuid, suppressed=suppressed, include_details=include_details
    )
    findings = _apply_finding_filters(
        findings, analysis_states=analysis_states, severities=severities
    )
    groups: list[AliasGroup] = _group_by_alias(findings)
    total_findings = sum(len(g["findings"]) for g in groups)
    page, page_size = _clamp_pagination(page, page_size, default=100)
    start = (page - 1) * page_size
    page_groups = groups[start : start + page_size]
    return {
        "total_groups": len(groups),
        "total_findings": total_findings,
        "page": page,
        "page_size": page_size,
        "groups": page_groups,
    }


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


def find_vulnerability(
    conn: Connection, *, vuln_id: str, source: str | None = None
) -> NormalizedVulnerability | None:
    """Look up a vulnerability, optionally specifying its source.

    When ``source`` is given, fetches directly from that namespace.
    When omitted, probes candidate sources inferred from the id prefix
    (CVE-* → NVD, GHSA-* → GITHUB, etc.) then falls back to other
    known sources. Returns the first hit, or ``None`` when nothing
    matches.

    Any error other than 404 (e.g. 5xx, auth) propagates immediately.
    """
    if source:
        try:
            return _get_vulnerability(conn, source=source, vuln_id=vuln_id)
        except DTrackHTTPError as e:
            if e.status_code == 404:
                return None
            raise
    sources = _candidate_sources(vuln_id)
    for s in sources:
        try:
            return _get_vulnerability(conn, source=s, vuln_id=vuln_id)
        except DTrackHTTPError as e:
            if e.status_code == 404:
                continue
            raise
        except DTrackAuthError:
            raise
    return None


def _get_vulnerability(
    conn: Connection, *, source: str, vuln_id: str
) -> NormalizedVulnerability:
    """Direct fetch by (source, vuln_id). Raises on 404."""
    raw = conn.get(f"/api/v1/vulnerability/source/{source}/vuln/{vuln_id}")
    if not raw:
        raise DTrackHTTPError(404, "empty vulnerability response", source)
    return normalize_vulnerability(raw)


def _candidate_sources(vuln_id: str) -> list[str]:
    """Order sources to probe based on the id's prefix."""
    vid = vuln_id.upper()
    primary: str | None = None
    if vid.startswith("CVE-"):
        primary = "NVD"
    elif vid.startswith("GHSA-"):
        primary = "GITHUB"
    elif vid.startswith("OSV-"):
        primary = "OSV"
    elif vid.startswith("SNYK-"):
        primary = "SNYK"
    if primary is None:
        return list(_KNOWN_SOURCES)
    return [primary] + [s for s in _KNOWN_SOURCES if s != primary]


def search_vulnerability(
    conn: Connection,
    *,
    vuln_id: str,
    active_only: bool = True,
    only_analyzed: bool = False,
) -> dict[str, Any] | None:
    """Find which projects are affected by a vulnerability.

    Resolves the vulnerability via :func:`find_vulnerability`, then
    queries DT for every project that contains it. Returns the
    vulnerability detail plus a per-project summary with analysis state.

    Read-only — no findings are fetched, only project-level metadata
    and the analysis for the specific (project, component, vuln) triple.
    """
    vuln = find_vulnerability(conn, vuln_id=vuln_id)
    if vuln is None:
        return None

    alias_keys = _alias_keys_for(vuln)
    projects: list[dict[str, Any]] = []
    visited: set[str] = set()

    for source, vid in sorted(alias_keys):
        path = f"/api/v1/vulnerability/source/{source}/vuln/{vid}/projects"
        try:
            raw_projects = conn.get(path) or []
        except DTrackHTTPError as e:
            if e.status_code == 404:
                continue
            raise
        if not isinstance(raw_projects, list):
            continue
        for p in raw_projects:
            if not isinstance(p, dict):
                continue
            p_uuid = p.get("uuid")
            if not p_uuid or p_uuid in visited:
                continue
            visited.add(p_uuid)
            if active_only and not bool(p.get("active", True)):
                continue
            proj = normalize_project(p)
            entry: dict[str, Any] = {
                "project": {
                    "uuid": proj["uuid"],
                    "name": proj["name"],
                    "version": proj["version"],
                    "active": proj["active"],
                    "audit_ratio": proj["metrics"]["audit_ratio"],
                },
                "analyses": [],
            }
            try:
                p_findings = _fetch_all_findings(conn, p_uuid, suppressed=True)
            except DTrackHTTPError as e:
                if e.status_code == 404:
                    projects.append(entry)
                    continue
                raise
            for f in p_findings:
                f_keys = _alias_keys_for(f["vulnerability"])
                if not (alias_keys & f_keys):
                    continue
                analysis = get_analysis(
                    conn,
                    project_uuid=p_uuid,
                    component_uuid=f["component"]["uuid"],
                    vulnerability_uuid=f["vulnerability"]["uuid"],
                )
                if only_analyzed and analysis.get("state") == "NOT_SET":
                    continue
                entry["analyses"].append({
                    "component": f["component"]["name"],
                    "component_version": f["component"].get("version"),
                    "state": analysis.get("state", "NOT_SET"),
                    "justification": analysis.get("justification"),
                })
            if not only_analyzed or entry["analyses"]:
                projects.append(entry)

    return {
        "vulnerability": vuln,
        "affected_projects": projects,
        "total_projects": len(projects),
    }


# ---------------------------------------------------------------------------
# Shared pagination helpers
# ---------------------------------------------------------------------------


def _clamp_page_size(value: int | None, *, default: int) -> int:
    if value is None or value <= 0:
        return default
    return min(value, _MAX_PAGE_SIZE)


def _clamp_pagination(
    page: int | None, page_size: int | None, *, default: int
) -> tuple[int, int]:
    return max(1, page or 1), _clamp_page_size(page_size, default=default)


# ---------------------------------------------------------------------------
# Analysis — read + (the only) write path
# ---------------------------------------------------------------------------


_VALID_WRITE_STATES: set[str] = {
    "NOT_SET",
    "IN_TRIAGE",
    "EXPLOITABLE",
    "FALSE_POSITIVE",
    "NOT_AFFECTED",
    "RESOLVED",
}


def get_analysis(
    conn: Connection,
    *,
    project_uuid: str,
    component_uuid: str,
    vulnerability_uuid: str,
) -> dict[str, Any]:
    """Fetch the analysis record for one (project, component, vuln) triple.

    Returns the normalized analysis (see :func:`_normalize_analysis`). If
    DT has no analysis row yet, returns the empty-analysis default
    (state ``NOT_SET``, no comments) so callers never have to null-check.
    """
    params = {
        "project": project_uuid,
        "component": component_uuid,
        "vulnerability": vulnerability_uuid,
    }
    try:
        raw = conn.get("/api/v1/analysis", params=params)
    except DTrackHTTPError as e:
        if e.status_code == 404:
            return _empty_analysis()
        raise
    if not raw:
        return _empty_analysis()
    return _normalize_analysis(raw)


def set_analysis(
    conn: Connection,
    *,
    project_uuid: str,
    component_uuid: str | None = None,
    vulnerability_uuid: str | None = None,
    finding: NormalizedFinding | None = None,
    state: str,
    justification: str | None = None,
    response: str | None = None,
    details: str | None = None,
    comment: str | None = None,
    suppressed: bool | None = None,
) -> dict[str, Any]:
    """Write an analysis record. The single mutation path in dtrack-mcp.

    Two ways to identify the finding:
      * Pass ``component_uuid`` and ``vulnerability_uuid`` directly.
      * Pass ``finding`` (a NormalizedFinding dict from list_findings /
        find_duplicate_analyses) — UUIDs are extracted automatically.

    When ``finding`` is provided, its UUIDs take precedence over any
    explicit ``component_uuid`` / ``vulnerability_uuid``.
    ``project_uuid`` is always required because findings from
    ``find_duplicate_analyses.other_projects`` may belong to a different
    project.

    Sends ``PUT /api/v1/analysis``. Fields left as ``None`` are omitted
    so DT keeps its current value. ``comment`` appends to the history.
    """
    if finding is not None:
        component = finding.get("component") or {}
        vulnerability = finding.get("vulnerability") or {}
        component_uuid = component.get("uuid")
        vulnerability_uuid = vulnerability.get("uuid")
        if not component_uuid:
            raise DTrackError(
                "finding is missing component.uuid — cannot derive component_uuid"
            )
        if not vulnerability_uuid:
            raise DTrackError(
                "finding is missing vulnerability.uuid — cannot derive "
                "vulnerability_uuid"
            )
    if not component_uuid or not vulnerability_uuid:
        raise DTrackError(
            "set_analysis requires either finding or both "
            "component_uuid and vulnerability_uuid"
        )
    state_upper = state.upper()
    if state_upper not in _VALID_WRITE_STATES:
        raise DTrackError(
            f"invalid analysis state {state!r}; "
            f"expected one of {sorted(_VALID_WRITE_STATES)}"
        )
    body: dict[str, Any] = {
        "project": project_uuid,
        "component": component_uuid,
        "vulnerability": vulnerability_uuid,
        "analysisState": state_upper,
    }
    if justification is not None:
        body["analysisJustification"] = justification
    if response is not None:
        body["analysisResponse"] = response
    if details is not None:
        body["analysisDetails"] = details
    if comment is not None:
        body["comment"] = comment
    if suppressed is not None:
        body["isSuppressed"] = bool(suppressed)
    raw = conn.put_json("/api/v1/analysis", body=body)
    if not raw:
        return _empty_analysis()
    return _normalize_analysis(raw)


def _normalize_analysis(raw: dict[str, Any]) -> dict[str, Any]:
    """Shape DT's analysis payload into a compact, serializable form."""
    comments_raw = raw.get("analysisComments") or []
    comments: list[dict[str, Any]] = []
    for c in comments_raw:
        if not isinstance(c, dict):
            continue
        comments.append(
            {
                "commenter": c.get("commenter"),
                "timestamp": epoch_ms_to_iso(c.get("timestamp")),
                "comment": c.get("comment", ""),
            }
        )
    state = raw.get("analysisState") or "NOT_SET"
    return {
        "state": state,
        "justification": raw.get("analysisJustification"),
        "response": raw.get("analysisResponse"),
        "details": raw.get("analysisDetails"),
        "is_suppressed": bool(raw.get("isSuppressed", False)),
        "comments": comments,
    }


def _empty_analysis() -> dict[str, Any]:
    return {
        "state": "NOT_SET",
        "justification": None,
        "response": None,
        "details": None,
        "is_suppressed": False,
        "comments": [],
    }


# ---------------------------------------------------------------------------
# Duplicate discovery for the triage loop
# ---------------------------------------------------------------------------


_TRIAGED_STATES: frozenset[str] = frozenset(
    {"EXPLOITABLE", "FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED", "IN_TRIAGE"}
)


def find_duplicate_analyses(
    conn: Connection,
    *,
    project_uuid: str,
    component_uuid: str,
    vulnerability_uuid: str,
    states: list[str] | None = None,
    only_analyzed: bool = False,
    active_only: bool = True,
    project_tag: str | None = None,
    compact: bool = False,
) -> dict[str, Any]:
    """Find analyses of duplicates of a finding, in three flavours.

    Given a finding identified by ``(project_uuid, component_uuid,
    vulnerability_uuid)``, return:

    1. ``aliases_in_project`` — other findings in the same project whose
       vulnerability is in the same alias cluster (different uuid, same
       real issue).
    2. ``same_vuln_other_components`` — other findings in the same
       project on different components but with the exact same
       vulnerability uuid.
    3. ``other_projects`` — findings in *other* DT projects that share
       any id in the target's alias cluster. Each carries its project
       (uuid/name/version) so the human can judge relevance.

    Each entry bundles component, vulnerability summary, and analysis
    (state + comments) so the caller sees prior triage decisions in one
    shot.

    Filters (v0.4):

    * ``states`` — whitelist of analysis state strings applied to all
      three output buckets. ``target`` is never filtered out.
    * ``only_analyzed`` — shorthand for ``states`` = every state except
      ``NOT_SET``. Ignored when ``states`` is non-empty (``states`` wins).
    * ``active_only`` (default **True**) — in ``other_projects``, skip
      DT projects flagged inactive. Does not affect the two same-project
      buckets, which are scoped to the project the caller already chose.
    * ``project_tag`` — in ``other_projects``, keep only DT projects
      carrying this tag (name-equality, case-insensitive).
    * ``compact`` — drop bulky fields from the returned payload. See
      SPEC §13.4.1 for the exact field list.
    """
    state_filter = _resolve_state_filter(states, only_analyzed)
    tag_filter = project_tag.lower() if project_tag else None

    project_findings = _fetch_all_findings(
        conn, project_uuid, suppressed=True
    )
    target = _find_target_finding(
        project_findings, component_uuid, vulnerability_uuid
    )
    if target is None:
        raise DTrackError(
            f"finding not found in project {project_uuid}: "
            f"component={component_uuid} vulnerability={vulnerability_uuid}"
        )

    alias_keys = _alias_keys_for(target["vulnerability"])

    aliases_in_project: list[dict[str, Any]] = []
    same_vuln_other_components: list[dict[str, Any]] = []
    for f in project_findings:
        if (
            f["component"]["uuid"] == component_uuid
            and f["vulnerability"]["uuid"] == vulnerability_uuid
        ):
            continue
        fv = f["vulnerability"]
        if fv["uuid"] == vulnerability_uuid:
            entry = _finding_with_analysis(conn, project_uuid, f)
            if _passes_state_filter(entry, state_filter):
                same_vuln_other_components.append(entry)
            continue
        f_keys = _alias_keys_for(fv)
        if alias_keys & f_keys:
            entry = _finding_with_analysis(conn, project_uuid, f)
            if _passes_state_filter(entry, state_filter):
                aliases_in_project.append(entry)

    other_projects = _collect_other_project_duplicates(
        conn,
        current_project=project_uuid,
        alias_keys=alias_keys,
        active_only=active_only,
        tag_filter=tag_filter,
        state_filter=state_filter,
    )

    target_analysis = get_analysis(
        conn,
        project_uuid=project_uuid,
        component_uuid=component_uuid,
        vulnerability_uuid=vulnerability_uuid,
    )

    result: dict[str, Any] = {
        "target": {
            "project_uuid": project_uuid,
            "component": target["component"],
            "vulnerability": target["vulnerability"],
            "analysis": target_analysis,
        },
        "aliases_in_project": aliases_in_project,
        "same_vuln_other_components": same_vuln_other_components,
        "other_projects": other_projects,
    }
    if compact:
        _apply_compact(result)
    return result


def _resolve_state_filter(
    states: list[str] | None, only_analyzed: bool
) -> frozenset[str] | None:
    """Return the effective set of allowed analysis states, or None = no filter.

    Precedence: ``states`` (when non-empty) wins over ``only_analyzed``.
    That's why ``only_analyzed`` is only consulted when ``states`` is
    falsy — an explicit list is always more specific than the shorthand.
    """
    if states:
        return frozenset(s.upper() for s in states)
    if only_analyzed:
        return _TRIAGED_STATES
    return None


def _passes_state_filter(
    entry: dict[str, Any], state_filter: frozenset[str] | None
) -> bool:
    if state_filter is None:
        return True
    state = (entry.get("analysis") or {}).get("state") or "NOT_SET"
    return state in state_filter


_COMPACT_COMMENT_PREVIEW_CHARS = 200


def _apply_compact(result: dict[str, Any]) -> None:
    """Strip bulky fields from every entry in-place. See SPEC §13.4.1."""
    _compact_entry(result.get("target"))
    for bucket in ("aliases_in_project", "same_vuln_other_components", "other_projects"):
        for entry in result.get(bucket) or []:
            _compact_entry(entry)


def _compact_entry(entry: dict[str, Any] | None) -> None:
    if not entry:
        return
    vuln = entry.get("vulnerability")
    if isinstance(vuln, dict):
        vuln["title"] = None
        vuln["description"] = None
        vuln["references"] = []
        vuln["cvss_v3_vector"] = None
        vuln["cvss_v4_vector"] = None
    component = entry.get("component")
    if isinstance(component, dict):
        component["purl_qualifiers"] = {}
        component["latest_version"] = None
    analysis = entry.get("analysis")
    if isinstance(analysis, dict):
        analysis["details"] = None
        comments = analysis.get("comments") or []
        for c in comments:
            if not isinstance(c, dict):
                continue
            body = c.get("comment") or ""
            if len(body) > _COMPACT_COMMENT_PREVIEW_CHARS:
                c["comment"] = body[:_COMPACT_COMMENT_PREVIEW_CHARS] + "..."


def _find_target_finding(
    findings: list[NormalizedFinding],
    component_uuid: str,
    vulnerability_uuid: str,
) -> NormalizedFinding | None:
    for f in findings:
        if (
            f["component"]["uuid"] == component_uuid
            and f["vulnerability"]["uuid"] == vulnerability_uuid
        ):
            return f
    return None


def _finding_with_analysis(
    conn: Connection, project_uuid: str, finding: NormalizedFinding
) -> dict[str, Any]:
    analysis = get_analysis(
        conn,
        project_uuid=project_uuid,
        component_uuid=finding["component"]["uuid"],
        vulnerability_uuid=finding["vulnerability"]["uuid"],
    )
    return {
        "component": finding["component"],
        "vulnerability": finding["vulnerability"],
        "analysis": analysis,
    }


def _collect_other_project_duplicates(
    conn: Connection,
    *,
    current_project: str,
    alias_keys: set[tuple[str, str]],
    active_only: bool = True,
    tag_filter: str | None = None,
    state_filter: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """Walk every alias, list projects hit by it, return matching findings.

    Implementation is intentionally straightforward: for each alias id
    we GET the list of projects from DT, then for each other project we
    fetch all findings and keep the ones whose vuln matches any alias
    key. It is N × M in the worst case; in practice alias_keys is tiny
    (2–5 entries) and the cross-project count is small.

    Filters (v0.4):

    * ``active_only`` — skip projects flagged inactive in DT.
    * ``tag_filter`` — if set, keep only projects carrying this tag
      (case-insensitive name equality).
    * ``state_filter`` — whitelist of analysis states applied to each
      finding before it is added to the result.
    """
    other: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    visited_projects: set[str] = set()

    for source, vuln_id in sorted(alias_keys):
        path = f"/api/v1/vulnerability/source/{source}/vuln/{vuln_id}/projects"
        try:
            raw_projects = conn.get(path) or []
        except DTrackHTTPError as e:
            if e.status_code == 404:
                continue
            raise
        if not isinstance(raw_projects, list):
            continue
        for p in raw_projects:
            if not isinstance(p, dict):
                continue
            p_uuid = p.get("uuid")
            if not p_uuid or p_uuid == current_project:
                continue
            if p_uuid in visited_projects:
                continue
            visited_projects.add(p_uuid)
            if active_only and not bool(p.get("active", True)):
                continue
            if tag_filter is not None and not _project_has_tag(p, tag_filter):
                continue
            try:
                p_findings = _fetch_all_findings(
                    conn, p_uuid, suppressed=True
                )
            except DTrackHTTPError as e:
                if e.status_code == 404:
                    continue
                raise
            project_meta = {
                "uuid": p_uuid,
                "name": p.get("name", ""),
                "version": p.get("version"),
            }
            for pf in p_findings:
                pf_keys = _alias_keys_for(pf["vulnerability"])
                if not (alias_keys & pf_keys):
                    continue
                key3 = (
                    p_uuid,
                    pf["component"]["uuid"],
                    pf["vulnerability"]["uuid"],
                )
                if key3 in seen:
                    continue
                entry = _finding_with_analysis(conn, p_uuid, pf)
                if not _passes_state_filter(entry, state_filter):
                    continue
                seen.add(key3)
                entry["project"] = project_meta
                other.append(entry)
    return other


def _project_has_tag(project: dict[str, Any], tag: str) -> bool:
    """Case-insensitive match of ``tag`` against DT project tags.

    DT ships tags as a list of ``{"name": "foo"}`` objects, but older
    payloads sometimes carry plain strings — handle both.
    """
    raw_tags = project.get("tags") or []
    if not isinstance(raw_tags, list):
        return False
    for t in raw_tags:
        if isinstance(t, dict):
            name = t.get("name")
        elif isinstance(t, str):
            name = t
        else:
            name = None
        if isinstance(name, str) and name.lower() == tag:
            return True
    return False


# ---------------------------------------------------------------------------
# Stage 3 / v0.2 — Version Lifecycle
# ---------------------------------------------------------------------------


def upload_bom(
    conn: Connection,
    *,
    project_name: str,
    project_version: str,
    bom: str,
    auto_create: bool = False,
    parent_name: str | None = None,
    parent_version: str | None = None,
) -> BomUploadResult:
    """Upload a CycloneDX/SPDX SBOM for (project_name, project_version).

    ``bom`` must be a base64-encoded document. We validate the encoding
    locally (decode round-trip) to give a clear error before hitting DT;
    the content itself is validated by DT asynchronously and surfaces
    through the returned token's processing endpoint (GET
    /api/v1/bom/token/{uuid}) — see ``get_project_versions``/clients
    for polling.
    """
    _require_base64(bom, field="bom")
    body: dict[str, Any] = {
        "projectName": project_name,
        "projectVersion": project_version,
        "autoCreate": bool(auto_create),
        "bom": bom,
    }
    if parent_name is not None:
        body["parentName"] = parent_name
    if parent_version is not None:
        body["parentVersion"] = parent_version

    raw = conn.post_json("/api/v1/bom", body=body) or {}
    token = str(raw.get("token") or "")
    project_uuid: str | None = None
    if auto_create:
        looked = _lookup_project(
            conn, name=project_name, version=project_version
        )
        if looked is not None:
            project_uuid = looked["uuid"]
    return BomUploadResult(
        token=token,
        project_uuid=project_uuid,
        message=(
            "Upload accepted, processing asynchronously. "
            "Use token to poll GET /api/v1/bom/token/{token}."
        ),
    )


def _require_base64(value: str, *, field: str) -> None:
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        preview = (value[:20] + "...") if len(value) > 20 else value
        raise DTrackError(
            f"{field} must be base64-encoded. Got {len(value)} chars "
            f"starting with {preview!r}: {e}"
        ) from e


def get_project_versions(
    conn: Connection, *, name: str, active_only: bool = True
) -> ProjectVersionsResult:
    """List all versions of a project by exact name.

    DT's ``searchText`` filter is substring-match, so we re-filter the
    results client-side for exact name equality. Versions are sorted
    descending with a semver-first, lexicographic-fallback key.
    """
    params: dict[str, Any] = {"pageSize": _MAX_PAGE_SIZE, "searchText": name}
    if active_only:
        params["excludeInactive"] = "true"
    raw = conn.get("/api/v1/project", params=params) or []
    items: list[NormalizedProject] = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        if p.get("name") != name:
            continue
        items.append(normalize_project(p))
    items.sort(key=_version_sort_key, reverse=True)
    return ProjectVersionsResult(name=name, total=len(items), versions=items)


def _version_sort_key(p: NormalizedProject) -> tuple[int, tuple[Any, ...], str]:
    """Return a key for sorting versions desc.

    Semver-aware: splits on dots, parses leading integers; non-numeric
    suffixes (``1.0.0-rc1``) keep numeric prefix and preserve the suffix
    lexicographically. Missing version sorts last. Caller uses
    ``reverse=True`` to get newest-first.
    """
    v = p.get("version") or ""
    if not v:
        return (0, (), "")
    parts: list[Any] = []
    for seg in v.split("."):
        num = ""
        rest = seg
        for ch in seg:
            if ch.isdigit():
                num += ch
            else:
                break
        rest = seg[len(num):]
        parts.append((int(num) if num else 0, rest))
    return (1, tuple(parts), v)


def diff_findings(
    conn: Connection,
    *,
    source_project_uuid: str,
    target_project_uuid: str,
    include_analysis: bool = True,
) -> DiffResult:
    """Compute carried / updated / new / gone between two project versions.

    See ``DOCS/v0.2_spec.md`` §3.3 for the full algorithm. Uses
    ``component_match_key`` (type, namespace, name) — NOT purl version
    or qualifiers — so DT 4.13→4.14 upgrades that add ``distro=...``
    to purls don't invalidate every match.
    """
    source_raw = conn.get(f"/api/v1/project/{source_project_uuid}") or {}
    target_raw = conn.get(f"/api/v1/project/{target_project_uuid}") or {}
    source_project = normalize_project(source_raw)
    target_project = normalize_project(target_raw)

    source_findings = _fetch_all_findings(
        conn, source_project_uuid, suppressed=False
    )
    target_findings = _fetch_all_findings(
        conn, target_project_uuid, suppressed=False
    )

    source_by_comp_key: dict[
        tuple[str, str, str], list[NormalizedFinding]
    ] = {}
    for sf in source_findings:
        key = component_match_key(sf["component"])
        source_by_comp_key.setdefault(key, []).append(sf)

    # Collision warnings: multi-arch / ambiguous match keys in source.
    warnings: list[str] = []
    for key, bucket in source_by_comp_key.items():
        distinct_purls = {
            f["component"].get("purl") or "" for f in bucket
        }
        if len(distinct_purls) >= 2:
            warnings.append(
                f"component_match_key {key} matches "
                f"{len(distinct_purls)} source components with different "
                f"purls: {sorted(distinct_purls)}. Matching may mix triage "
                f"from different variants."
            )

    carried: list[CarriedMatch] = []
    updated: list[UpdatedMatch] = []
    new_items: list[NormalizedFinding] = []
    consumed_source_ids: set[tuple[str, str]] = set()

    for tf in target_findings:
        t_key = component_match_key(tf["component"])
        t_vuln_keys = _alias_keys_for(tf["vulnerability"])
        bucket = source_by_comp_key.get(t_key, [])
        match, reason = _pick_source_match(tf, bucket, t_vuln_keys)
        if match is None:
            new_items.append(tf)
            continue
        consumed_source_ids.add(_finding_id(match))
        src_analysis = (
            _safe_get_analysis(conn, source_project_uuid, match)
            if include_analysis
            else None
        )
        if reason in ("exact_purl", "exact_alias"):
            carried.append(
                CarriedMatch(
                    target_finding=tf,
                    source_finding=match,
                    source_analysis=src_analysis,
                    match_reason=reason,
                )
            )
        else:
            updated.append(
                UpdatedMatch(
                    target_finding=tf,
                    source_finding=match,
                    source_analysis=src_analysis,
                    match_reason=reason,
                    component_version_from=match["component"].get("version"),
                    component_version_to=tf["component"].get("version"),
                )
            )

    target_comp_keys = {
        component_match_key(tf["component"]) for tf in target_findings
    }
    gone: list[GoneMatch] = []
    for sf in source_findings:
        if _finding_id(sf) in consumed_source_ids:
            continue
        s_key = component_match_key(sf["component"])
        src_analysis = (
            _safe_get_analysis(conn, source_project_uuid, sf)
            if include_analysis
            else None
        )
        reason_g = (
            "vuln_fixed" if s_key in target_comp_keys else "component_removed"
        )
        gone.append(
            GoneMatch(
                source_finding=sf,
                source_analysis=src_analysis,
                reason=reason_g,
            )
        )

    stats = DiffStats(
        carried=len(carried),
        updated_component=len(updated),
        new=len(new_items),
        gone=len(gone),
    )
    return DiffResult(
        source_project=source_project,
        target_project=target_project,
        carried=carried,
        updated_component=updated,
        new=new_items,
        gone=gone,
        stats=stats,
        warnings=warnings,
    )


def _finding_id(f: NormalizedFinding) -> tuple[str, str]:
    return (f["component"]["uuid"], f["vulnerability"]["uuid"])


def _pick_source_match(
    target: NormalizedFinding,
    source_bucket: list[NormalizedFinding],
    target_vuln_keys: set[tuple[str, str]],
) -> tuple[NormalizedFinding | None, MatchReason | None]:
    """Pick the best source match for a target finding.

    Priority: exact_purl > exact_alias > same_component_diff_version >
    alias_diff_component_version. Returns ``(None, None)`` when no
    source in the bucket shares any vulnerability alias.
    """
    t_purl = target["component"].get("purl")
    t_ver = target["component"].get("version")
    exact_purl: NormalizedFinding | None = None
    exact_alias: NormalizedFinding | None = None
    same_comp_diff_ver: NormalizedFinding | None = None
    alias_diff_ver: NormalizedFinding | None = None
    t_primary = (
        target["vulnerability"]["source"],
        target["vulnerability"]["vuln_id"],
    )

    for sf in source_bucket:
        s_keys = _alias_keys_for(sf["vulnerability"])
        if not (s_keys & target_vuln_keys):
            continue
        s_purl = sf["component"].get("purl")
        s_ver = sf["component"].get("version")
        primary_match = (
            sf["vulnerability"]["source"],
            sf["vulnerability"]["vuln_id"],
        ) == t_primary
        if s_purl and t_purl and s_purl == t_purl and primary_match:
            exact_purl = sf
            break
        if s_ver == t_ver:
            if primary_match and exact_alias is None:
                exact_alias = sf
            elif exact_alias is None:
                exact_alias = sf
        else:
            if primary_match and same_comp_diff_ver is None:
                same_comp_diff_ver = sf
            elif alias_diff_ver is None:
                alias_diff_ver = sf

    if exact_purl is not None:
        return exact_purl, "exact_purl"
    if exact_alias is not None:
        return exact_alias, "exact_alias"
    if same_comp_diff_ver is not None:
        return same_comp_diff_ver, "same_component_diff_version"
    if alias_diff_ver is not None:
        return alias_diff_ver, "alias_diff_component_version"
    return None, None


def _safe_get_analysis(
    conn: Connection, project_uuid: str, finding: NormalizedFinding
) -> NormalizedAnalysis | None:
    try:
        raw = get_analysis(
            conn,
            project_uuid=project_uuid,
            component_uuid=finding["component"]["uuid"],
            vulnerability_uuid=finding["vulnerability"]["uuid"],
        )
    except DTrackHTTPError:
        return None
    return raw  # type: ignore[return-value]


def carry_over_triage(
    conn: Connection,
    *,
    source_project_uuid: str,
    target_project_uuid: str,
    mode: str = "dry_run",
    include_updated_components: bool = False,
    overwrite_not_set: bool = True,
    overwrite_any: bool = False,
    comment_prefix: str = "[dtrack-mcp]",
    max_operations: int = 500,
) -> CarryOverResult:
    """Transfer triage decisions from source project version to target.

    Always call with ``mode="dry_run"`` first; only run ``mode="exact"``
    after the human approved the plan.

    ``max_operations`` caps how many writes we will attempt in ``exact``
    mode. Set as a sanity bound against LLM hallucination (a model
    convinced every one of 5000 findings should move). In ``dry_run``
    the cap is not enforced — the full plan is visible so the caller can
    decide to split.
    """
    if mode not in ("dry_run", "exact"):
        raise DTrackError(
            f"invalid mode {mode!r}; expected 'dry_run' or 'exact'"
        )

    diff = diff_findings(
        conn,
        source_project_uuid=source_project_uuid,
        target_project_uuid=target_project_uuid,
        include_analysis=True,
    )
    candidates: list[tuple[NormalizedFinding, NormalizedFinding,
                           NormalizedAnalysis | None, MatchReason]] = []
    for m in diff["carried"]:
        candidates.append(
            (m["target_finding"], m["source_finding"],
             m["source_analysis"], m["match_reason"])
        )
    if include_updated_components:
        for m in diff["updated_component"]:
            candidates.append(
                (m["target_finding"], m["source_finding"],
                 m["source_analysis"], m["match_reason"])
            )

    if mode == "exact" and len(candidates) > max_operations:
        raise DTrackError(
            f"plan contains {len(candidates)} operations, exceeds "
            f"max_operations={max_operations}. Either raise the cap "
            f"explicitly or split into batches."
        )

    details: list[CarryOverItemResult] = []
    transferred = skipped = failed = 0
    delay_ms = _write_delay_ms()

    for idx, (tf, sf, src_analysis, reason) in enumerate(candidates, start=1):
        action, skip_reason = _decide_action(
            tf, src_analysis, overwrite_not_set, overwrite_any
        )
        if action == "skipped":
            skipped += 1
            details.append(
                CarryOverItemResult(
                    finding=tf,
                    action="skipped",
                    reason=skip_reason,
                    match_reason=reason,
                    analysis_written=None,
                    error=None,
                )
            )
            continue

        if mode == "dry_run":
            transferred += 1
            details.append(
                CarryOverItemResult(
                    finding=tf,
                    action="transferred",
                    reason="dry_run plan (no write)",
                    match_reason=reason,
                    analysis_written=src_analysis,
                    error=None,
                )
            )
            continue

        if src_analysis is None:
            raise DTrackError(
                "internal: src_analysis is None for non-skipped carry-over "
                "candidate — _decide_action should have skipped it"
            )
        try:
            comment = _build_carry_comment(
                comment_prefix, diff["source_project"], src_analysis, reason
            )
            written_raw = set_analysis(
                conn,
                project_uuid=target_project_uuid,
                component_uuid=tf["component"]["uuid"],
                vulnerability_uuid=tf["vulnerability"]["uuid"],
                state=src_analysis["state"],
                justification=src_analysis.get("justification"),
                response=src_analysis.get("response"),
                details=src_analysis.get("details"),
                comment=comment,
                suppressed=src_analysis.get("is_suppressed"),
            )
            transferred += 1
            logger.info(
                "carry_over %d/%d: %s → transferred",
                idx,
                len(candidates),
                tf["vulnerability"].get("vuln_id"),
            )
            details.append(
                CarryOverItemResult(
                    finding=tf,
                    action="transferred",
                    reason=f"wrote analysis state={src_analysis['state']}",
                    match_reason=reason,
                    analysis_written=written_raw,  # type: ignore[arg-type]
                    error=None,
                )
            )
        except DTrackError as e:
            failed += 1
            logger.warning(
                "carry_over %d/%d: %s → failed: %s",
                idx,
                len(candidates),
                tf["vulnerability"].get("vuln_id"),
                e,
            )
            details.append(
                CarryOverItemResult(
                    finding=tf,
                    action="failed",
                    reason="write error",
                    match_reason=reason,
                    analysis_written=None,
                    error=str(e),
                )
            )

        if delay_ms > 0 and idx < len(candidates):
            time.sleep(delay_ms / 1000)

    return CarryOverResult(
        mode=mode,  # type: ignore[arg-type]
        transferred=transferred,
        skipped=skipped,
        failed=failed,
        details=details,
    )


def _decide_action(
    target: NormalizedFinding,
    src_analysis: NormalizedAnalysis | None,
    overwrite_not_set: bool,
    overwrite_any: bool,
) -> tuple[str, str]:
    """Return ``(action, reason)`` for a single carry-over candidate."""
    if src_analysis is None or src_analysis["state"] == "NOT_SET":
        return "skipped", "source has no actionable analysis"
    tgt_state = target["analysis"]["state"]
    if tgt_state == "NOT_SET":
        if not overwrite_not_set:
            return "skipped", "target is NOT_SET and overwrite_not_set=False"
        return "transfer", ""
    if overwrite_any:
        return "transfer", ""
    return "skipped", f"target already triaged as {tgt_state}"


def _build_carry_comment(
    prefix: str,
    source_project: NormalizedProject,
    src_analysis: NormalizedAnalysis,
    match_reason: MatchReason,
) -> str:
    existing = ""
    for c in reversed(src_analysis.get("comments") or []):
        text = (c.get("comment") or "").strip()
        if text:
            existing = text
            break
    return (
        f"{prefix} Carried from {source_project['name']} "
        f"{source_project.get('version') or '(no version)'}. "
        f"Match: {match_reason}. "
        f"Original comment: {existing or '(empty)'}"
    )


def _write_delay_ms() -> int:
    try:
        return max(0, int(os.environ.get("DTRACK_WRITE_DELAY_MS", "0")))
    except ValueError:
        return 0


def broadcast_triage(
    conn: Connection,
    *,
    reference_project_uuid: str,
    project_name: str,
    mode: str = "dry_run",
    include_updated_components: bool = False,
    overwrite_not_set: bool = True,
    overwrite_any: bool = False,
    comment_prefix: str = "[dtrack-mcp]",
    max_operations: int = 500,
    active_only: bool = True,
) -> BroadcastResult:
    """Propagate triage decisions from one version to all other versions.

    Fetches all versions of ``project_name``, excludes the reference
    version, and calls :func:`carry_over_triage` for each remaining
    version. Useful when a new CVE is found simultaneously in several
    versions — triage once and fan out in every direction.

    Always run with ``mode="dry_run"`` first. The reference project is
    the one with the decisions to broadcast; it can be any version, not
    necessarily the newest.
    """
    ref = _get_project(conn, project_uuid=reference_project_uuid)
    if ref is None:
        raise DTrackHTTPError(404, f"Reference project {reference_project_uuid!r} not found", "/api/v1/project")

    versions = get_project_versions(conn, name=project_name, active_only=active_only)
    targets = [v for v in versions["versions"] if v["uuid"] != reference_project_uuid]

    target_results: list[BroadcastTargetResult] = []
    transferred_total = 0
    skipped_total = 0
    failed_total = 0

    for t in targets:
        result = carry_over_triage(
            conn,
            source_project_uuid=reference_project_uuid,
            target_project_uuid=t["uuid"],
            mode=mode,
            include_updated_components=include_updated_components,
            overwrite_not_set=overwrite_not_set,
            overwrite_any=overwrite_any,
            comment_prefix=comment_prefix,
            max_operations=max_operations,
        )
        transferred_total += result["transferred"]
        skipped_total += result["skipped"]
        failed_total += result["failed"]
        target_results.append(
            BroadcastTargetResult(
                uuid=t["uuid"],
                version=t.get("version"),
                is_latest=t.get("is_latest", False),
                result=result,
            )
        )

    summary = BroadcastSummary(
        targets_total=len(targets),
        transferred_total=transferred_total,
        skipped_total=skipped_total,
        failed_total=failed_total,
    )
    return BroadcastResult(
        reference=ref,
        mode=mode,  # type: ignore[arg-type]
        targets=target_results,
        summary=summary,
    )
