"""MCP server entry point for dtrack-mcp.

Thin wrappers around :mod:`dtrack_mcp.api`. The rule here is: validate
inputs, call the api function, return the result. No data logic in this
file — if you're tempted to add some, put it in ``api.py`` or
``normalize.py`` and call it from here.

**Read-mostly.** Every tool here is a GET against Dependency-Track
except :func:`set_analysis`, which is the only write path. The
connection-layer guard restricts writes to ``PUT /api/v1/analysis``
and nothing else. See ``feedback_dtrack_readonly.md``.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import api
from .connection import Connection, DTrackConfig, DTrackError
from .validation import seal_schemas, validated

logger = logging.getLogger("dtrack_mcp")

mcp = FastMCP("dtrack-mcp")

# Lazy singleton. Built on first tool invocation so import-time failures
# (missing env vars) don't kill the MCP handshake before the client sees
# a useful error.
_connection: Connection | None = None


def _conn() -> Connection:
    global _connection
    if _connection is None:
        config = DTrackConfig.from_env()
        _connection = Connection(config)
        logger.info(
            "dtrack_mcp: connected to %s (auth=%s)",
            config.base_url,
            "api_key" if config.has_api_key() else "login",
        )
    return _connection


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
@validated
def list_projects(
    name_filter: str | None = None,
    active_only: bool = True,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """List Dependency-Track projects.

    List projects in the Dependency-Track instance, optionally filtered
    by a substring of the project name. Returns normalized projects with
    per-severity vulnerability counts. Read-only.

    Args:
        name_filter: Case-insensitive substring on project name.
        active_only: If true, exclude projects marked inactive in DT.
        page: 1-based page number.
        page_size: Items per page (max 500).
    """
    return api.list_projects(
        _conn(),
        name_filter=name_filter,
        active_only=active_only,
        page=page,
        page_size=page_size,
    )


@mcp.tool()
@validated
def resolve_project(
    project_uuid: str | None = None,
    name: str | None = None,
    version: str | None = None,
) -> dict[str, Any] | None:
    """Resolve a project by UUID or by exact (name, version).

    Two lookup paths — use whichever you have:
      * ``project_uuid`` — direct UUID lookup (e.g. copied from the DT
        UI URL or returned by another tool).
      * ``name`` + ``version`` — exact-match lookup by project name and
        version string.

    When ``project_uuid`` is provided it takes precedence; ``name`` and
    ``version`` are ignored. Returns a normalized project, or null if
    nothing matches. Read-only.

    Args:
        project_uuid: DT project UUID. Takes precedence when provided.
        name: Exact project name (requires ``version``).
        version: Exact project version (requires ``name``).
    """
    return api.resolve_project(
        _conn(), project_uuid=project_uuid, name=name, version=version
    )


@mcp.tool()
@validated
def list_findings(
    project_uuid: str,
    suppressed: bool = False,
    analysis_states: list[str] | None = None,
    severities: list[str] | None = None,
    page: int = 1,
    page_size: int = 100,
    include_details: bool = False,
) -> dict[str, Any]:
    """List vulnerability findings for a project with optional filters.

    Returns normalized findings — each one bundles the vulnerability
    (severity, CVSS v3/v4, CWE, EPSS, aliases), the affected component
    (name, version, purl, latest known version), and the analysis state.
    All filters are applied client-side before pagination, so ``total``
    reflects the post-filter count. Read-only.

    When ``include_details=True``, every finding's vulnerability summary
    also carries ``title``, ``description``, and ``references`` so an
    LLM can draft a verdict without a separate ``get_vulnerability``
    call. Off by default because descriptions can be 2–4 KB each — set
    it to ``true`` only for focused batches (20–30 findings), not
    project-wide scans.

    Args:
        project_uuid: DT project UUID (get it from list_projects or lookup_project).
        suppressed: Include findings suppressed by an analyst.
        analysis_states: Whitelist, e.g. ["NOT_SET", "IN_TRIAGE", "EXPLOITABLE",
            "FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED"].
        severities: Whitelist, e.g. ["CRITICAL", "HIGH", "MEDIUM", "LOW",
            "UNASSIGNED"].
        page: 1-based page number (applied after filtering).
        page_size: Items per page (max 500).
        include_details: If true, embed title/description/references in
            each finding's vulnerability summary (v0.3). Default false.
    """
    return api.list_findings(
        _conn(),
        project_uuid=project_uuid,
        suppressed=suppressed,
        analysis_states=analysis_states,
        severities=severities,
        page=page,
        page_size=page_size,
        include_details=include_details,
    )


@mcp.tool()
@validated
def find_vulnerability(
    vuln_id: str, source: str | None = None
) -> dict[str, Any] | None:
    """Fetch the full detail record of a vulnerability.

    When ``source`` is given (e.g. "NVD", "GITHUB"), fetches directly.
    When omitted, probes candidate sources based on the id prefix
    (CVE-* → NVD, GHSA-* → GITHUB, etc.) and returns the first hit,
    or null if nothing matches. Read-only.

    Returns title, description, CVSS v2/v3/v4 scores and vectors, CWEs,
    EPSS score and percentile, KEV flag, references, and alias list.

    Args:
        vuln_id: Vulnerability id, e.g. "CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz".
        source: Optional DT source namespace — "NVD", "GITHUB", "OSV",
            "SNYK", "SONATYPE", "VULNDB", "INTERNAL", etc. When omitted
            the source is inferred from the id prefix.
    """
    return api.find_vulnerability(_conn(), vuln_id=vuln_id, source=source)


@mcp.tool()
@validated
def search_vulnerability(
    vuln_id: str,
    active_only: bool = True,
    only_analyzed: bool = False,
) -> dict[str, Any] | None:
    """Search which projects are affected by a vulnerability.

    Given a vulnerability id (e.g. "CVE-2024-1234"), resolves it,
    then finds every DT project that contains a finding for this
    vulnerability (or any of its aliases). For each project returns
    the analysis state per affected component.

    Use this to answer "which products are affected by CVE-X and
    what's been decided?" without manually iterating over projects.
    Read-only.

    Args:
        vuln_id: Vulnerability id (e.g. "CVE-2024-1234", "GHSA-xxxx").
        active_only: Skip inactive/archived projects. Default True.
        only_analyzed: Only include projects/findings with a
            non-NOT_SET analysis state. Default False.
    """
    return api.search_vulnerability(
        _conn(),
        vuln_id=vuln_id,
        active_only=active_only,
        only_analyzed=only_analyzed,
    )


@mcp.tool()
@validated
def group_findings_by_alias(
    project_uuid: str,
    suppressed: bool = False,
    analysis_states: list[str] | None = None,
    severities: list[str] | None = None,
    page: int = 1,
    page_size: int = 100,
    include_details: bool = False,
) -> dict[str, Any]:
    """Group findings by alias (transitive closure) — dedup CVE/GHSA/OSV.

    Vulnerabilities reported under different ids (e.g. CVE-2024-X and
    GHSA-Y-Z) often refer to the same issue and are linked via DT's
    aliases. This tool runs union-find over that alias graph and returns
    one cluster per real issue. Each cluster carries a canonical id
    (CVE first, then GHSA, then OSV, then SNYK, then INTERNAL, then
    alphabetical), the full alias list, a ``merge_reason`` trace of the
    edges that joined the cluster, and every finding in the project
    belonging to it.

    Same filters as list_findings. Pagination applies to groups, not to
    the findings inside them — a group always ships with all its
    findings intact. Sorted by highest CVSS score (v3 or v4) descending.
    Read-only.

    ``include_details=True`` (v0.3) embeds title/description/references
    in every finding's vulnerability summary. The same description text
    repeats on each finding inside a group — acceptable tradeoff for a
    single-call triage flow.

    Args:
        project_uuid: DT project UUID.
        suppressed: Include suppressed findings.
        analysis_states: Whitelist of analysis state strings.
        severities: Whitelist of severity strings.
        page: 1-based page of groups (not findings).
        page_size: Groups per page (max 500).
        include_details: If true, embed title/description/references in
            each finding's vulnerability summary (v0.3). Default false.
    """
    return api.group_findings_by_alias(
        _conn(),
        project_uuid=project_uuid,
        suppressed=suppressed,
        analysis_states=analysis_states,
        severities=severities,
        page=page,
        page_size=page_size,
        include_details=include_details,
    )


@mcp.tool()
@validated
def get_analysis(
    project_uuid: str,
    component_uuid: str,
    vulnerability_uuid: str,
) -> dict[str, Any]:
    """Fetch the analysis record for one finding.

    Returns the analysis state, justification, response, details,
    suppressed flag, and the full comment history. If DT has no analysis
    row yet, returns an empty-analysis default (state ``NOT_SET``, no
    comments) — callers never get null. Read-only.

    Args:
        project_uuid: DT project UUID.
        component_uuid: DT component UUID inside that project.
        vulnerability_uuid: DT vulnerability UUID.
    """
    return api.get_analysis(
        _conn(),
        project_uuid=project_uuid,
        component_uuid=component_uuid,
        vulnerability_uuid=vulnerability_uuid,
    )


@mcp.tool()
@validated
def find_duplicate_analyses(
    project_uuid: str,
    component_uuid: str,
    vulnerability_uuid: str,
    states: list[str] | None = None,
    only_analyzed: bool = False,
    active_only: bool = True,
    project_tag: str | None = None,
    compact: bool = False,
) -> dict[str, Any]:
    """Find analyses of duplicates of a finding across DT.

    Given one finding, returns three parallel lists of duplicates with
    their current analysis (state + comment history), intended for a
    triage loop that wants to reuse prior decisions:

      * ``aliases_in_project`` — other findings in the same project in
        the same alias cluster (CVE ↔ GHSA ↔ OSV of the same issue).
      * ``same_vuln_other_components`` — same vulnerability uuid on
        other components/versions in the same project.
      * ``other_projects`` — findings in other DT projects that share
        any id in the target's alias cluster; each entry carries its
        project uuid/name/version.

    Each entry bundles ``{component, vulnerability, analysis}``; entries
    in ``other_projects`` also carry ``project``. Read-only.

    Filters (v0.4):
      * ``states`` — whitelist of analysis states (e.g.
        ``["NOT_AFFECTED","EXPLOITABLE"]``) applied to all three output
        buckets. ``target`` is never filtered.
      * ``only_analyzed`` — shorthand for every state except NOT_SET.
        Ignored when ``states`` is non-empty (``states`` wins).
      * ``active_only`` (default **True**) — skip archived/inactive DT
        projects in ``other_projects``. v0.4 default flip — existing
        callers that don't pass the flag stop seeing archived hits.
      * ``project_tag`` — in ``other_projects`` only, keep projects
        carrying this tag (case-insensitive name equality).
      * ``compact`` — strip bulky fields (description, CVSS vectors,
        analysis details, long comment bodies truncated to 200 chars).
        See SPEC §13.4.1 for the exact field list.

    Args:
        project_uuid: DT project UUID of the target finding.
        component_uuid: DT component UUID of the target finding.
        vulnerability_uuid: DT vulnerability UUID of the target finding.
        states: Whitelist of analysis state strings, e.g.
            ``["NOT_AFFECTED","EXPLOITABLE"]``.
        only_analyzed: If true, keep only entries with a non-NOT_SET
            analysis. Ignored when ``states`` is non-empty.
        active_only: If true (default), skip archived projects in
            ``other_projects``.
        project_tag: Optional DT tag name; restricts ``other_projects``
            to projects carrying this tag (case-insensitive).
        compact: If true, strip bulky fields from the payload.
    """
    return api.find_duplicate_analyses(
        _conn(),
        project_uuid=project_uuid,
        component_uuid=component_uuid,
        vulnerability_uuid=vulnerability_uuid,
        states=states,
        only_analyzed=only_analyzed,
        active_only=active_only,
        project_tag=project_tag,
        compact=compact,
    )


@mcp.tool()
@validated
def set_analysis(
    project_uuid: str,
    state: str,
    component_uuid: str | None = None,
    vulnerability_uuid: str | None = None,
    finding: dict[str, Any] | None = None,
    justification: str | None = None,
    response: str | None = None,
    details: str | None = None,
    comment: str | None = None,
    suppressed: bool | None = None,
) -> dict[str, Any]:
    """⚠ WRITE. Update the analysis record for one finding.

    Two ways to identify the finding:
      * Pass ``component_uuid`` and ``vulnerability_uuid`` directly.
      * Pass ``finding`` — a NormalizedFinding dict as returned by
        ``list_findings``, ``group_findings_by_alias``, or entries
        inside ``find_duplicate_analyses``. The UUIDs are extracted
        automatically, avoiding copy-paste errors in the triage loop.

    When ``finding`` is provided, its UUIDs take precedence.
    ``project_uuid`` is always required because findings from
    ``find_duplicate_analyses`` → ``other_projects`` may belong to a
    different project.

    Issues ``PUT /api/v1/analysis``; the connection-layer guard refuses
    any other write path. Fields left as ``None`` are omitted from the
    body, so DT keeps its current value. ``comment`` appends to the
    history, it does not replace existing comments. Returns the full
    normalized analysis after the write.

    Args:
        project_uuid: DT project UUID.
        state: One of NOT_SET, IN_TRIAGE, EXPLOITABLE, FALSE_POSITIVE,
            NOT_AFFECTED, RESOLVED.
        component_uuid: DT component UUID (required unless ``finding``
            is provided).
        vulnerability_uuid: DT vulnerability UUID (required unless
            ``finding`` is provided).
        finding: A NormalizedFinding dict. When provided, component_uuid
            and vulnerability_uuid are extracted from it.
        justification: Optional CycloneDX justification enum
            (e.g. CODE_NOT_REACHABLE, REQUIRES_CONFIGURATION).
        response: Optional response enum (e.g. CAN_NOT_FIX, WILL_NOT_FIX,
            UPDATE, ROLLBACK, WORKAROUND_AVAILABLE).
        details: Optional free-text analysis details.
        comment: Optional free-text comment appended to the history.
        suppressed: Optional bool to suppress/unsuppress the finding.
    """
    return api.set_analysis(
        _conn(),
        project_uuid=project_uuid,
        component_uuid=component_uuid,
        vulnerability_uuid=vulnerability_uuid,
        finding=finding,  # type: ignore[arg-type]
        state=state,
        justification=justification,
        response=response,
        details=details,
        comment=comment,
        suppressed=suppressed,
    )


# ---------------------------------------------------------------------------
# Stage 3 / v0.2 — Version Lifecycle tools
# ---------------------------------------------------------------------------


@mcp.tool()
@validated
def upload_bom(
    project_name: str,
    project_version: str,
    bom: str,
    auto_create: bool = False,
    parent_name: str | None = None,
    parent_version: str | None = None,
) -> dict[str, Any]:
    """⚠ WRITE. Upload a CycloneDX/SPDX SBOM to Dependency-Track.

    Issues ``POST /api/v1/bom`` with the SBOM as a base64-encoded
    string. Returns an upload ``token`` — the caller should poll
    ``GET /api/v1/bom/token/{token}`` (not an MCP tool in v0.2) to
    detect when processing finishes and findings become visible.
    When ``auto_create=True``, the project is created if missing; this
    requires the ``PROJECT_CREATION_UPLOAD`` permission in DT.

    Args:
        project_name: Target project name (must exist unless auto_create=True).
        project_version: Target project version.
        bom: Base64-encoded SBOM document (CycloneDX or SPDX).
        auto_create: Create project/version if missing. Requires extra permission.
        parent_name: Optional parent project name for hierarchy.
        parent_version: Optional parent project version.
    """
    return dict(
        api.upload_bom(
            _conn(),
            project_name=project_name,
            project_version=project_version,
            bom=bom,
            auto_create=auto_create,
            parent_name=parent_name,
            parent_version=parent_version,
        )
    )


@mcp.tool()
@validated
def get_project_versions(
    name: str, active_only: bool = True
) -> dict[str, Any]:
    """List all versions of a project by exact name.

    Returns ``{name, total, versions}`` where versions are sorted newest
    first (semver-aware, lexicographic fallback). Used to pick source /
    target UUIDs for ``diff_findings`` and ``carry_over_triage``.
    Read-only.

    Args:
        name: Exact project name.
        active_only: Exclude projects marked inactive in DT.
    """
    return dict(
        api.get_project_versions(_conn(), name=name, active_only=active_only)
    )


@mcp.tool()
@validated
def diff_findings(
    source_project_uuid: str,
    target_project_uuid: str,
    include_analysis: bool = True,
) -> dict[str, Any]:
    """Compute carried / updated_component / new / gone between two versions.

    Typical use: upgrading a product v1 → v2. ``source`` is v1 (where
    triage decisions already exist), ``target`` is v2 (new SBOM just
    uploaded). Returns four lists:

      * ``carried`` — same component + same vulnerability, safe to
        transfer analyses 1:1.
      * ``updated_component`` — same vulnerability, component version
        changed (patch or major). Decision may or may not still apply.
      * ``new`` — appeared in target only.
      * ``gone`` — were in source only; reason is ``vuln_fixed``
        (component still there) or ``component_removed``.

    Component matching uses ``(purl_type, purl_namespace, purl_name)`` —
    deliberately drops qualifiers so DT 4.13→4.14 upgrades that add
    ``distro=...`` don't invalidate every match. Ambiguous matches
    (multi-arch SBOMs with the same component at different qualifiers)
    emit an entry in ``warnings``. Read-only.

    Args:
        source_project_uuid: Old version UUID (usually with existing triage).
        target_project_uuid: New version UUID.
        include_analysis: Load current analysis for each source finding
            (needed for carry_over; adds one HTTP call per finding).
    """
    return dict(
        api.diff_findings(
            _conn(),
            source_project_uuid=source_project_uuid,
            target_project_uuid=target_project_uuid,
            include_analysis=include_analysis,
        )
    )


@mcp.tool()
@validated
def carry_over_triage(
    source_project_uuid: str,
    target_project_uuid: str,
    mode: str = "dry_run",
    include_updated_components: bool = False,
    overwrite_not_set: bool = True,
    overwrite_any: bool = False,
    comment_prefix: str = "[dtrack-mcp]",
    max_operations: int = 500,
) -> dict[str, Any]:
    """⚠ WRITE (when mode="exact"). Transfer triage decisions v1 → v2.

    ALWAYS run with ``mode="dry_run"`` first. Only switch to
    ``mode="exact"`` after a human has reviewed the plan. In exact mode
    each transfer issues ``PUT /api/v1/analysis`` and appends a comment
    noting the source project and match reason. The full history of
    source comments is preserved in the original project untouched.

    Skip rules:
      * source has no actionable analysis (state NOT_SET) → skipped
      * target already triaged (state ≠ NOT_SET) and overwrite_any=False → skipped
      * target NOT_SET and overwrite_not_set=False → skipped

    Safety caps:
      * ``max_operations`` (default 500) early-fails in exact mode when
        the plan is larger than the cap. Raise explicitly for huge
        transfers, or split into batches.
      * ``DTRACK_WRITE_DELAY_MS`` env var adds a per-write sleep for
        rate-limit-sensitive instances.

    Args:
        source_project_uuid: Old version UUID with existing triage.
        target_project_uuid: New version UUID to populate.
        mode: "dry_run" (no writes, returns plan) or "exact" (performs writes).
        include_updated_components: Also transfer updated_component matches
            (same CVE, different component version). Default False — conservative.
        overwrite_not_set: Transfer over target entries in state NOT_SET. Default True.
        overwrite_any: Transfer over target entries in any state. Default False.
        comment_prefix: Prepended to every carry-over comment.
        max_operations: Sanity cap against hallucination-driven bulk writes
            in exact mode. Raise if you genuinely need to transfer more.
    """
    return dict(
        api.carry_over_triage(
            _conn(),
            source_project_uuid=source_project_uuid,
            target_project_uuid=target_project_uuid,
            mode=mode,
            include_updated_components=include_updated_components,
            overwrite_not_set=overwrite_not_set,
            overwrite_any=overwrite_any,
            comment_prefix=comment_prefix,
            max_operations=max_operations,
        )
    )


# ---------------------------------------------------------------------------
# v0.6 — Broadcast triage
# ---------------------------------------------------------------------------


@mcp.tool()
@validated
def broadcast_triage(
    reference_project_uuid: str,
    project_name: str,
    mode: str = "dry_run",
    include_updated_components: bool = False,
    overwrite_not_set: bool = True,
    overwrite_any: bool = False,
    comment_prefix: str = "[dtrack-mcp]",
    max_operations: int = 500,
    active_only: bool = True,
) -> dict[str, Any]:
    """⚠ WRITE (when mode="exact"). Fan out triage decisions to all versions.

    A specialised form of ``carry_over_triage`` for the case where a new
    CVE is found simultaneously in multiple versions of the same product.
    Instead of running carry_over N times, triage the finding once in any
    version, then call this tool to propagate the decision in all
    directions (newer AND older versions).

    Steps:
      1. Fetches every version of ``project_name`` from DT.
      2. Excludes the reference version.
      3. Calls ``carry_over_triage(reference → target)`` for each.
      4. Returns per-target results plus an aggregate summary.

    ALWAYS run ``mode="dry_run"`` first to review the plan.

    Args:
        reference_project_uuid: UUID of the version that already has the
            triage decision to broadcast.
        project_name: Exact project name (used to find all other versions).
        mode: "dry_run" (no writes) or "exact" (performs writes).
        include_updated_components: Also transfer updated_component matches.
            Default False — conservative.
        overwrite_not_set: Transfer over targets in state NOT_SET. Default True.
        overwrite_any: Transfer over targets in any state. Default False.
        comment_prefix: Prepended to every carry-over comment.
        max_operations: Per-target cap. Raise if a single target needs more.
        active_only: Skip inactive/archived versions. Default True.
    """
    return dict(
        api.broadcast_triage(
            _conn(),
            reference_project_uuid=reference_project_uuid,
            project_name=project_name,
            mode=mode,
            include_updated_components=include_updated_components,
            overwrite_not_set=overwrite_not_set,
            overwrite_any=overwrite_any,
            comment_prefix=comment_prefix,
            max_operations=max_operations,
            active_only=active_only,
        )
    )


seal_schemas(mcp)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("DTRACK_LOG_LEVEL", "INFO"),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        mcp.run()
    except DTrackError as e:
        logger.error("dtrack_mcp startup failed: %s", e)
        raise SystemExit(2) from e


if __name__ == "__main__":
    main()
