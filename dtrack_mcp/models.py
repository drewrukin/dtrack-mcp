"""Normalized response shapes returned by dtrack-mcp tools.

TypedDicts here are the contract. Any change in field names or types is a
spec change — update ``SPEC.md`` §6 in the same commit.

Timestamps are ISO-8601 UTC strings (``YYYY-MM-DDTHH:MM:SSZ``). Epoch ms
from Dependency-Track are converted in ``normalize.py``.
"""

from __future__ import annotations

from typing import Literal, TypedDict

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED"]

AnalysisState = Literal[
    "NOT_SET",
    "IN_TRIAGE",
    "EXPLOITABLE",
    "FALSE_POSITIVE",
    "NOT_AFFECTED",
    "RESOLVED",
]


class VulnerabilityRef(TypedDict):
    """Compact (source, id) pair used inside aliases and canonical ids."""

    source: str
    vuln_id: str


class ProjectMetrics(TypedDict):
    vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    unassigned: int
    findings_total: int
    findings_audited: int
    findings_unaudited: int
    inherited_risk_score: float
    audit_ratio: float | None


class NormalizedProject(TypedDict):
    uuid: str
    name: str
    version: str | None
    classifier: str
    active: bool
    is_latest: bool
    first_seen: str | None
    last_seen: str | None
    metrics: ProjectMetrics


class NormalizedComponent(TypedDict):
    uuid: str
    name: str
    version: str | None
    group: str | None
    purl: str | None
    purl_type: str | None
    purl_namespace: str | None
    purl_name: str | None
    purl_version: str | None
    purl_qualifiers: dict[str, str]
    latest_version: str | None


class NormalizedVulnerability(TypedDict):
    uuid: str
    source: str
    vuln_id: str
    title: str | None
    description: str | None
    severity: Severity
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    cvss_v4_score: float | None
    cvss_v4_vector: str | None
    cvss_v2_score: float | None
    cwes: list[int]
    epss_score: float | None
    epss_percentile: float | None
    in_kev: bool
    published: str | None
    updated: str | None
    references: list[str]
    aliases: list[VulnerabilityRef]
    affected_components_count: int | None


class FindingVulnerabilitySummary(TypedDict):
    """Subset of NormalizedVulnerability embedded into NormalizedFinding.

    Carries what an LLM needs to triage a finding. ``title``,
    ``description``, ``references`` are populated only when the caller
    passes ``include_details=True`` (v0.3); otherwise they are
    ``None`` / ``[]`` to keep the list payload compact. A full
    ``get_vulnerability`` call is still needed for CVSS history,
    ``affected_components_count``, and the complete alias graph.
    """

    uuid: str
    source: str
    vuln_id: str
    severity: Severity
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    cvss_v4_score: float | None
    cvss_v4_vector: str | None
    cwes: list[int]
    epss_score: float | None
    in_kev: bool
    aliases: list[VulnerabilityRef]
    title: str | None
    description: str | None
    references: list[str]


class FindingAnalysis(TypedDict):
    state: AnalysisState
    justification: str | None
    is_suppressed: bool


class NormalizedFinding(TypedDict):
    vulnerability: FindingVulnerabilitySummary
    component: NormalizedComponent
    analysis: FindingAnalysis
    attributed_on: str | None


class AliasGroup(TypedDict):
    """Cluster of findings whose vulnerabilities are aliases of each other.

    ``merge_reason`` traces the edges of the alias graph that caused the
    cluster to form, in order of addition. Useful for sanity-checking a
    merge that spans many id namespaces.
    """

    canonical_id: VulnerabilityRef
    aliases: list[VulnerabilityRef]
    merge_reason: list[str]
    findings: list[NormalizedFinding]


class AnalysisComment(TypedDict):
    commenter: str | None
    timestamp: str | None
    comment: str


class NormalizedAnalysis(TypedDict):
    state: AnalysisState
    justification: str | None
    response: str | None
    details: str | None
    is_suppressed: bool
    comments: list[AnalysisComment]


# ---- Stage 3 / v0.2: Version Lifecycle ---------------------------------


class BomUploadResult(TypedDict):
    token: str
    project_uuid: str | None
    message: str


class ProjectVersionsResult(TypedDict):
    name: str
    total: int
    versions: list[NormalizedProject]


MatchReason = Literal[
    "exact_purl",
    "exact_alias",
    "same_component_diff_version",
    "alias_diff_component_version",
]

GoneReason = Literal["component_removed", "vuln_fixed"]


class CarriedMatch(TypedDict):
    target_finding: NormalizedFinding
    source_finding: NormalizedFinding
    source_analysis: NormalizedAnalysis | None
    match_reason: MatchReason


class UpdatedMatch(TypedDict):
    target_finding: NormalizedFinding
    source_finding: NormalizedFinding
    source_analysis: NormalizedAnalysis | None
    match_reason: MatchReason
    component_version_from: str | None
    component_version_to: str | None


class GoneMatch(TypedDict):
    source_finding: NormalizedFinding
    source_analysis: NormalizedAnalysis | None
    reason: GoneReason


class DiffStats(TypedDict):
    carried: int
    updated_component: int
    new: int
    gone: int


class DiffResult(TypedDict):
    source_project: NormalizedProject
    target_project: NormalizedProject
    carried: list[CarriedMatch]
    updated_component: list[UpdatedMatch]
    new: list[NormalizedFinding]
    gone: list[GoneMatch]
    stats: DiffStats
    warnings: list[str]


CarryOverAction = Literal["transferred", "skipped", "conflict", "failed"]
CarryOverMode = Literal["dry_run", "exact"]


class CarryOverItemResult(TypedDict):
    finding: NormalizedFinding
    action: CarryOverAction
    reason: str
    match_reason: MatchReason
    analysis_written: NormalizedAnalysis | None
    error: str | None


class CarryOverResult(TypedDict):
    mode: CarryOverMode
    transferred: int
    skipped: int
    failed: int
    details: list[CarryOverItemResult]


# ---- v0.6: Broadcast triage -------------------------------------------


class BroadcastSummary(TypedDict):
    targets_total: int
    transferred_total: int
    skipped_total: int
    failed_total: int


class BroadcastTargetResult(TypedDict):
    uuid: str
    version: str | None
    is_latest: bool
    result: CarryOverResult


class BroadcastResult(TypedDict):
    reference: NormalizedProject
    mode: CarryOverMode
    targets: list[BroadcastTargetResult]
    summary: BroadcastSummary
