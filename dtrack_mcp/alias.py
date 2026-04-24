"""Group findings by transitive alias closure using union-find.

Two findings belong to the same group if their vulnerabilities are
connected in the alias graph. Connection can be direct (finding A's vuln
has B in its aliases list) or transitive (A↔B↔C makes {A,B,C} one group
even if A and C are not directly linked).

The canonical id of a group is chosen by a fixed source priority, so the
most recognizable identifier (typically CVE) leads the cluster in output.

See SPEC §6.6 and §7.6.
"""

from __future__ import annotations

from typing import Iterable

from .models import (
    AliasGroup,
    FindingVulnerabilitySummary,
    NormalizedComponent,
    NormalizedFinding,
    NormalizedVulnerability,
    VulnerabilityRef,
)

# Lower index = higher priority when picking a canonical id. Any source
# not listed falls to the bottom and is broken alphabetically.
_SOURCE_PRIORITY: list[str] = ["NVD", "GITHUB", "OSV", "SNYK", "INTERNAL"]


def _priority(source: str) -> tuple[int, str]:
    """Sort key: (priority index, source name for alphabetical tiebreak)."""
    try:
        return (_SOURCE_PRIORITY.index(source), source)
    except ValueError:
        return (len(_SOURCE_PRIORITY), source)


def _ref_key(ref: VulnerabilityRef) -> tuple[str, str]:
    return (ref["source"], ref["vuln_id"])


def _ref_str(ref: VulnerabilityRef) -> str:
    return f"{ref['source']}/{ref['vuln_id']}"


class _UnionFind:
    """Tiny union-find keyed by (source, vuln_id) tuples.

    Also records the sequence of edges that caused each merge so callers
    can audit how a cluster was assembled.
    """

    def __init__(self) -> None:
        self._parent: dict[tuple[str, str], tuple[str, str]] = {}
        self._rank: dict[tuple[str, str], int] = {}
        # component-id (= root key) -> list of "A↔B" edge strings
        self._merge_log: dict[tuple[str, str], list[str]] = {}

    def add(self, ref: VulnerabilityRef) -> None:
        key = _ref_key(ref)
        if key not in self._parent:
            self._parent[key] = key
            self._rank[key] = 0
            self._merge_log[key] = []

    def find(self, key: tuple[str, str]) -> tuple[str, str]:
        root = key
        while self._parent[root] != root:
            root = self._parent[root]
        # path compression
        while self._parent[key] != root:
            nxt = self._parent[key]
            self._parent[key] = root
            key = nxt
        return root

    def union(self, a: VulnerabilityRef, b: VulnerabilityRef) -> None:
        self.add(a)
        self.add(b)
        if _ref_key(a) == _ref_key(b):
            # Self-edge — DT stores a vulnerability's own id in its own
            # aliases list, so we see it during traversal. Not an edge.
            return
        ra = self.find(_ref_key(a))
        rb = self.find(_ref_key(b))
        # Canonicalize edge direction so A↔B and B↔A produce the same string.
        lo, hi = sorted([_ref_str(a), _ref_str(b)])
        edge = f"{lo}↔{hi}"
        if ra == rb:
            # Already in the same cluster — still record the edge as a
            # redundant link so merge_reason reflects every alias present
            # in the data.
            if edge not in self._merge_log[ra]:
                self._merge_log[ra].append(edge)
            return
        # Union by rank; merge smaller log into larger.
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1
        merged = self._merge_log[ra] + self._merge_log[rb]
        if edge not in merged:
            merged.append(edge)
        self._merge_log[ra] = merged
        self._merge_log[rb] = []  # root moved

    def components(self) -> dict[tuple[str, str], list[tuple[str, str]]]:
        groups: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for key in self._parent:
            root = self.find(key)
            groups.setdefault(root, []).append(key)
        return groups

    def merge_log(self, root: tuple[str, str]) -> list[str]:
        return list(self._merge_log.get(root, []))


def canonical_ref(refs: Iterable[VulnerabilityRef]) -> VulnerabilityRef:
    """Pick the canonical id from a set of refs.

    Precedence: NVD > GITHUB > OSV > SNYK > INTERNAL > others (alphabetical).
    Within the same source, lowest ``vuln_id`` lexicographically wins.
    """
    return min(refs, key=lambda r: (_priority(r["source"]), r["vuln_id"]))


def group_findings_by_alias(
    findings: list[NormalizedFinding],
) -> list[AliasGroup]:
    """Cluster findings by transitive alias closure.

    Each finding's primary vulnerability ``(source, vuln_id)`` is treated
    as a node. Every alias listed on that vulnerability becomes an edge
    to another node. Connected components are the resulting clusters.

    A finding is attached to exactly one cluster — the one containing its
    primary vulnerability. Within a cluster, findings are preserved in
    input order.

    Cluster sort order in the returned list:
      1. highest ``cvss_v3_score`` or ``cvss_v4_score`` across the cluster,
         descending (``None`` sorts last);
      2. ``canonical_id.vuln_id`` ascending as tiebreak.
    """
    uf = _UnionFind()

    # Pre-index findings by their primary (source, vuln_id) for later
    # assignment to clusters. One key may map to multiple findings if the
    # same vuln affects several components in the project.
    findings_by_key: dict[tuple[str, str], list[NormalizedFinding]] = {}
    for f in findings:
        primary: VulnerabilityRef = {
            "source": f["vulnerability"]["source"],
            "vuln_id": f["vulnerability"]["vuln_id"],
        }
        uf.add(primary)
        findings_by_key.setdefault(_ref_key(primary), []).append(f)
        for alias in f["vulnerability"]["aliases"]:
            uf.union(primary, alias)

    groups: list[AliasGroup] = []
    for root, members in uf.components().items():
        member_refs: list[VulnerabilityRef] = [
            {"source": s, "vuln_id": v} for (s, v) in members
        ]
        canonical = canonical_ref(member_refs)
        # Order aliases deterministically: canonical first, then by priority.
        ordered_aliases = sorted(
            member_refs, key=lambda r: (_priority(r["source"]), r["vuln_id"])
        )
        attached: list[NormalizedFinding] = []
        for key in members:
            attached.extend(findings_by_key.get(key, []))
        if not attached:
            # Pure alias-only node with no finding attached — happens when
            # an alias references a vuln that isn't in the project. Skip.
            continue
        groups.append(
            AliasGroup(
                canonical_id=canonical,
                aliases=ordered_aliases,
                merge_reason=uf.merge_log(root),
                findings=attached,
            )
        )

    groups.sort(key=_group_sort_key)
    return groups


def component_match_key(c: NormalizedComponent) -> tuple[str, str, str]:
    """Stable identity for a component across DT versions.

    Uses ``(purl_type, purl_namespace, purl_name)`` — deliberately drops
    ``purl_version`` and ``purl_qualifiers``. DT 4.14 added a ``distro``
    qualifier to purls of deb/rpm components, which would otherwise mask
    every component as "new" after upgrading DT. Version is compared
    separately at match time to distinguish carried vs updated findings.

    Falls back to ``("", "", <name>)`` when purl is missing or unparseable
    so plain-name components still cluster together.
    """
    ptype = c.get("purl_type") or ""
    ns = c.get("purl_namespace") or ""
    name = c.get("purl_name") or c.get("name") or ""
    return (ptype, ns, name)


def vuln_match_keys(
    vuln: FindingVulnerabilitySummary | NormalizedVulnerability | dict,
) -> set[tuple[str, str]]:
    """Return ``{(source, vuln_id)}`` for a vuln plus every alias it carries.

    Accepts any mapping with ``source``, ``vuln_id``, and ``aliases`` —
    both ``FindingVulnerabilitySummary`` and ``NormalizedVulnerability``
    fit. Missing ``aliases`` is treated as empty.
    """
    keys: set[tuple[str, str]] = {(vuln["source"], vuln["vuln_id"])}
    for a in vuln.get("aliases", []) or []:
        keys.add((a["source"], a["vuln_id"]))
    return keys


def _group_sort_key(g: AliasGroup) -> tuple[float, str]:
    """Sort by max CVSS (v3 or v4) desc, then by canonical vuln_id asc."""
    max_score = 0.0
    for f in g["findings"]:
        v = f["vulnerability"]
        for s in (v["cvss_v3_score"], v["cvss_v4_score"]):
            if s is not None and s > max_score:
                max_score = s
    return (-max_score, g["canonical_id"]["vuln_id"])
