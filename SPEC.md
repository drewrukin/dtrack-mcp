# dtrack-mcp — Spec

Read-mostly MCP server for Dependency-Track. Lets an LLM pull the data
needed to draft a security defect from findings in DT, and (Stage 2)
write back the analyst triage decision via a single narrow write path.

**Status:** v0.7.1 shipped (Stage 8). Current stable feature surface is
14 tools (§16.1), strict input validation (§15), version lifecycle
(§11), duplicate discovery with compact mode (§13), broadcast triage
(v0.6), cross-project vulnerability search (§16.2), and transient-
failure retry (§17). Changes here require sign-off.

Reading order for a newcomer: §1–6 (goals + normalized schemas, still
authoritative), §7 (individual tool contracts — §7.2 and §7.4 are
marked **Superseded** where merged in v0.7, see §16.1), then §11–17
for the per-stage evolution.

---

## 1. Goal

Given a Dependency-Track project, retrieve the vulnerabilities affecting it
in a shape compact enough to fit an LLM context, with enough detail to
draft a Yandex Tracker defect: CVE id, severity, CVSS vector, CWE,
description, EPSS/KEV signals, affected component + version, analysis
state, and the alias cluster that links findings reported under different
identifiers (CVE ↔ GHSA ↔ OSV).

## 2. Scope

### In scope
- Project lookup (list, exact match by name+version)
- Findings per project with filters (severity, analysis state, suppressed)
- Vulnerability details (incl. EPSS, KEV, aliases)
- Alias-based deduplication of findings (transitive union-find)
- Vulnerability lookup by id across sources
- **Analysis read** — `GET /api/v1/analysis` for state + comment history
- **Analysis write** — `PUT /api/v1/analysis` for triage decisions
  (the only mutation path, strictly allowlisted at the HTTP guard —
  DT v4 uses PUT, not POST, see §3.1)
- **Duplicate discovery** across alias clusters, same-vuln-other-component,
  and other DT projects, with prior analyses attached

### Out of scope
- Policy violations, licenses
- Metrics/trend history
- Component inventory without vulnerabilities
- BOM upload and BOM download
- Any other mutation: suppress endpoint, create/update/delete project,
  user/team/permission changes, admin endpoints
- Cross-project search beyond duplicate discovery, audit logs

## 3. Hard invariants

### 3.1 Read-mostly: (method, path) allowlist

**dtrack-mcp must not modify Dependency-Track state except through the
documented analysis write path.** The connection module enforces this
at the HTTP-client boundary via `Connection._guard(method, path)`. The
allowlist, in full:

| Method | Path | Purpose |
|---|---|---|
| `GET` | *any* | All read traffic |
| `PUT` | `/api/v1/analysis` | Analyst triage (state, comment, etc.) — DT v4 records decisions via PUT, not POST |
| `POST` | `/api/v1/bom` | CycloneDX SBOM upload (v0.2 `upload_bom`) |
| `POST` | `/api/v1/user/login` | Authentication, handled in `_login` — deliberately bypasses the data-plane guard |

Any other method/path combination raises `RuntimeError` before hitting
the network. The allowlist is exact-match, not prefix-match:
`/api/v1/analysis/` or `/api/v1/analysisX` are refused.

This invariant is non-negotiable. Reason: production DT with real SBOMs
of Arenadata products; the test account has broad write permissions
(BOM_UPLOAD, VULNERABILITY_MANAGEMENT, POLICY_MANAGEMENT) that must
never be exercised by the server. Adding anything to the allowlist is a
deliberate spec change, not a refactor.

See `feedback_dtrack_readonly.md` in Claude memory and
`tests/test_guard.py` for the exhaustive allowlist lock.

### 3.2 No secrets in logs or responses

Credentials come from environment variables only. Logs go to stderr in
JSON-line format; the JWT and api key are never logged. API responses are
never echoed verbatim into tool output — they are normalized first.

### 3.3 Response size discipline

Raw DT responses are bulky (a single project JSON can exceed 1 MB).
Normalized tool output must fit a reasonable LLM context: target < 20 KB
for a typical `list_findings` call on a medium project. Strip raw
`metrics{}`, raw `directDependencies`, server-side aggregates, and any
field not listed in the normalized schemas below.

## 4. Authentication

Two modes, auto-selected from env at startup:

| Mode | Env | Header |
|---|---|---|
| API key | `DTRACK_API_KEY` | `X-Api-Key: <key>` |
| Login+password | `DTRACK_USER`, `DTRACK_PASSWORD` | `Authorization: Bearer <jwt>` |

If both are set, API key wins. JWT is fetched lazily on first request,
re-fetched once on 401 and the original request retried.

JWT lifetime observed against DT 4.14.1: **7 days**. Server does not cache
across process restarts.

## 5. Configuration (env)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DTRACK_URL` | yes | — | Base URL, e.g. `https://dtrack.adsw.io/` |
| `DTRACK_API_KEY` | either this | — | API key (preferred in prod) |
| `DTRACK_USER` | or this pair | — | Login (stage 1 default) |
| `DTRACK_PASSWORD` | | — | Password |
| `DTRACK_VERIFY_TLS` | no | `false` | Set `true` only if DT has a trusted cert |
| `DTRACK_TIMEOUT` | no | `30` | Request timeout, seconds |
| `DTRACK_RETRY_MAX` | no | `3` | Retries on transient failures (see §17) |
| `DTRACK_RETRY_BACKOFF_MS` | no | `500` | Base backoff in milliseconds |

Proxies are disabled inside the client (`trust_env=False`) — DT is an
internal host and the corporate proxy refuses to tunnel it. Equivalent to
`curl --noproxy '*'`.

## 6. Normalized schemas

All tools return these shapes. Timestamps are ISO-8601 UTC strings.

### 6.1 NormalizedProject

```
{
  "uuid": str,
  "name": str,
  "version": str | null,
  "classifier": str,            // APPLICATION / CONTAINER / LIBRARY / ...
  "active": bool,
  "is_latest": bool,
  "first_seen": str | null,     // ISO-8601
  "last_seen": str | null,      // ISO-8601
  "metrics": {
    "vulnerabilities": int,
    "critical": int,
    "high": int,
    "medium": int,
    "low": int,
    "unassigned": int,
    "findings_total": int,
    "findings_audited": int,
    "findings_unaudited": int,
    "inherited_risk_score": float,
    "audit_ratio": float | null           // v0.4: audited / total, null when total=0
  }
}
```

### 6.2 NormalizedComponent

```
{
  "uuid": str,
  "name": str,
  "version": str | null,
  "group": str | null,
  "purl": str | null,           // opaque PURL string for display
  "purl_type": str | null,      // "deb", "maven", "npm", ...  — parsed from purl
  "purl_namespace": str | null, // "debian", "org.apache", ...
  "purl_name": str | null,
  "purl_version": str | null,
  "purl_qualifiers": dict,      // {"distro": "bookworm", "arch": "amd64"}
  "latest_version": str | null  // if DT knows
}
```

The parsed `purl_*` fields (v0.2+) feed `component_match_key` for diff
and carry-over matching. DT 4.14 added a `distro` qualifier to
`deb`/`rpm` purls; matching by `(purl_type, purl_namespace, purl_name)`
drops qualifiers deliberately so upgrading DT does not mask every
component as "new".

### 6.3 VulnerabilityRef

Compact reference used inside aliases and canonical identifiers.

```
{
  "source": str,                // "NVD" / "GITHUB" / "OSV" / "SNYK" / "INTERNAL" / ...
  "vuln_id": str                // "CVE-2024-1234" / "GHSA-xxxx-yyyy-zzzz" / ...
}
```

### 6.4 NormalizedVulnerability

```
{
  "uuid": str,
  "source": str,
  "vuln_id": str,
  "title": str | null,
  "description": str | null,
  "severity": str,              // CRITICAL / HIGH / MEDIUM / LOW / UNASSIGNED
  "cvss_v3_score": float | null,
  "cvss_v3_vector": str | null,
  "cvss_v4_score": float | null,
  "cvss_v4_vector": str | null,
  "cvss_v2_score": float | null,
  "cwes": [int],
  "epss_score": float | null,
  "epss_percentile": float | null,
  "in_kev": bool,               // false if DT didn't tell us
  "published": str | null,      // ISO-8601
  "updated": str | null,        // ISO-8601
  "references": [str],          // URLs extracted from DT markdown blob
  "aliases": [VulnerabilityRef],// flattened: one DT alias object may yield multiple refs
  "affected_components_count": int | null
}
```

### 6.5 NormalizedFinding

```
{
  "vulnerability": {
    "uuid": str,
    "source": str,
    "vuln_id": str,
    "severity": str,
    "cvss_v3_score": float | null,
    "cvss_v3_vector": str | null,
    "cvss_v4_score": float | null,
    "cvss_v4_vector": str | null,
    "cwes": [int],
    "epss_score": float | null,
    "in_kev": bool,
    "aliases": [VulnerabilityRef],
    "title":       str | null,   // v0.3: populated when caller passes include_details=true
    "description": str | null,   // v0.3: populated when caller passes include_details=true
    "references":  [str]         // v0.3: populated when caller passes include_details=true
  },
  "component": NormalizedComponent,
  "analysis": {
    "state": str,               // NOT_SET / IN_TRIAGE / EXPLOITABLE / FALSE_POSITIVE / NOT_AFFECTED / RESOLVED
    "justification": str | null,
    "is_suppressed": bool
  },
  "attributed_on": str | null   // ISO-8601
}
```

When ``include_details=false`` (default), ``title`` and ``description``
are ``null`` and ``references`` is ``[]`` — the keys are always present
to keep the TypedDict shape stable.

### 6.6 AliasGroup

```
{
  "canonical_id": VulnerabilityRef,  // highest-priority id in the cluster
  "aliases": [VulnerabilityRef],     // all ids in the cluster, incl canonical
  "merge_reason": [str],             // human-readable trace of edges that joined the cluster, e.g. ["CVE-2024-1↔GHSA-x", "GHSA-x↔OSV-y"]
  "findings": [NormalizedFinding]    // all findings in the project whose vulnerability belongs to this cluster
}
```

**Canonical id selection** — first match wins:
1. `NVD` (CVE)
2. `GITHUB` (GHSA)
3. `OSV`
4. `SNYK`
5. `INTERNAL`
6. Anything else — alphabetical by `source`, then `vuln_id`

**Alias closure** — transitive via union-find. If `A↔B` and `B↔C` then
`{A, B, C}` form one group even if `A` and `C` are not directly linked.

## 7. Tools

Current surface — 14 tools (v0.7). Entries #1–9 are Stage 1+2; #10–14
were added in later stages (§11, §13, v0.6) and are specified in those
sections. This table is the single source of truth for the public
tool-name set.

| #  | Name | R/W | Stage | Purpose |
|----|---|---|---|---|
| 1  | `list_projects` | R | Stage 1 | Browse projects, optional name filter |
| 2  | `resolve_project` | R | Stage 1 (v0.7 rename) | Find project by UUID or exact (name, version). Merges `lookup_project` + `get_project` — see §16.1 |
| 3  | `list_findings` | R | Stage 1 | Findings for a project, with filters |
| 4  | `find_vulnerability` | R | Stage 1 (v0.7 merge) | Full vuln detail; optional `source`, probes when omitted — merges `get_vulnerability`, see §16.1 |
| 5  | `search_vulnerability` | R | v0.7 (new) | Which projects are affected by a given CVE? — §16.2 |
| 6  | `group_findings_by_alias` | R | Stage 1 | `list_findings` + union-find on aliases |
| 7  | `get_analysis` | R | Stage 2 | State + comment history for one (project, component, vuln) |
| 8  | `find_duplicate_analyses` | R | Stage 2 (v0.4 filters) | 3-way duplicate discovery with prior analyses — §13.3, §13.4.1 |
| 9  | `set_analysis` | **W** | Stage 2 (v0.7 merge) | `PUT /api/v1/analysis`. Accepts raw UUIDs or a `finding` dict — §16.1 |
| 10 | `upload_bom` | **W** | v0.2 | CycloneDX/SPDX SBOM upload — §11.1 |
| 11 | `get_project_versions` | R | v0.2 | All versions of a project, newest first — §11.2 |
| 12 | `diff_findings` | R | v0.2 | Carried / updated / new / gone between two versions — §11.3 |
| 13 | `carry_over_triage` | **W** | v0.2 | Transfer decisions source → target (dry-run default) — §11.4 |
| 14 | `broadcast_triage` | **W** | v0.6 | Fan out one decision to every version of a product |

Sections below describe each tool's current input shape. The
`include_raw` parameter mentioned in earlier drafts was never
implemented and was removed from the spec in v0.7 (see §16.4). Debug
output is controlled by the `DTRACK_LOG_LEVEL=DEBUG` env var instead.

### 7.1 `list_projects`

**Input**
```
{
  "name_filter": str | null,       // substring, case-insensitive
  "active_only": bool = true,
  "page": int = 1,
  "page_size": int = 50            // max 500
}
```

**Output**
```
{
  "total": int,
  "page": int,
  "page_size": int,
  "items": [NormalizedProject]
}
```

**DT endpoint:** `GET /api/v1/project?pageNumber={page}&pageSize={page_size}&name={name_filter}`.

### 7.2 `lookup_project` (**Superseded in v0.7** — merged into `resolve_project`)

Kept here for historical reference. The DT endpoint and semantics are
unchanged; the MCP tool name is now `resolve_project` which accepts
either a UUID or (name, version). See §16.1.

**Historic input**
```
{
  "name": str,                     // required
  "version": str                   // required
}
```

**Output:** one `NormalizedProject` or `null` when nothing matches.

**DT endpoint:** `GET /api/v1/project/lookup?name={name}&version={version}`.

### 7.3 `list_findings`

**Input**
```
{
  "project_uuid": str,
  "suppressed": bool = false,                // include suppressed?
  "analysis_states": [str] | null,           // e.g. ["NOT_SET","EXPLOITABLE"]
  "severities": [str] | null,                // e.g. ["CRITICAL","HIGH"]
  "page": int = 1,
  "page_size": int = 100,                    // max 500
  "include_details": bool = false            // v0.3: see §12
}
```

**Output**
```
{
  "total": int,                              // after filtering
  "page": int,
  "page_size": int,
  "items": [NormalizedFinding]
}
```

**Filter semantics.** All filters are applied **client-side** on the full
finding set returned by DT for the project. Filtering happens **before**
pagination: the `total` reflects the post-filter count, `page`/`page_size`
slice the filtered list.

**DT endpoint:** `GET /api/v1/finding/project/{uuid}`.

**Errors.** Unknown `project_uuid` → `DTrackHTTPError` (not null).

### 7.4 `get_vulnerability` (**Superseded in v0.7** — merged into `find_vulnerability`)

Kept for historical reference. In v0.7 this became the optional
explicit-source path of `find_vulnerability`; pass `source` directly
instead of calling this tool. See §16.1.

**Historic input**
```
{
  "source": str,                             // "NVD", "GITHUB", ...
  "vuln_id": str                             // "CVE-2024-1234"
}
```

**Output:** `NormalizedVulnerability` or raises if not found.

**DT endpoint:** `GET /api/v1/vulnerability/source/{source}/vuln/{vuln_id}`.

### 7.5 `find_vulnerability`

**Input** (v0.7: `source` became optional)
```
{
  "vuln_id": str,                            // any id
  "source":  str | null = null               // when omitted, inferred from the id prefix
}
```

**Output:** `NormalizedVulnerability` or `null` when no source yields a hit.

**Algorithm.** When `source` is given, fetch directly from that DT
namespace. When omitted, infer candidate sources from the `vuln_id`
prefix (`CVE-*` → `NVD`; `GHSA-*` → `GITHUB`; `OSV-*` → `OSV`; `SNYK-*`
→ `SNYK`; otherwise try all known sources). Probe sequentially, return
the first 200. On all-404, return `null`.

### 7.6 `group_findings_by_alias`

**Input:** same as `list_findings`, plus nothing extra.

**Output**
```
{
  "total_groups": int,
  "total_findings": int,
  "groups": [AliasGroup]
}
```

**Algorithm.**
1. Call `list_findings` (same filters applied).
2. For each finding, fetch `aliases` from its vulnerability (already
   present in DT finding response — no extra request needed).
3. Build a graph: node = `(source, vuln_id)`; edge = alias relation.
4. Union-find to compute connected components.
5. For each component:
   - pick canonical id by source priority (see §6.6),
   - list all member ids as aliases,
   - collect the edges that joined the cluster into `merge_reason`,
   - attach every finding whose vuln belongs to the component.
6. Sort groups by the maximum CVSS v3 score of their findings (desc),
   then by `canonical_id.vuln_id`.

**Pagination.** `page`/`page_size` are applied to **groups**, not to the
findings inside them. A group always ships with all its findings intact
(to keep the cluster meaningful).

### 7.7 `get_analysis`

**Input**
```
{
  "project_uuid": str,
  "component_uuid": str,
  "vulnerability_uuid": str
}
```

**Output — `NormalizedAnalysis`:**
```
{
  "state": str,                   // NOT_SET / IN_TRIAGE / EXPLOITABLE / FALSE_POSITIVE / NOT_AFFECTED / RESOLVED
  "justification": str | null,
  "response": str | null,
  "details": str | null,
  "is_suppressed": bool,
  "comments": [                   // full history in DT order
    {"commenter": str | null, "timestamp": str | null, "comment": str}
  ]
}
```

**DT endpoint:** `GET /api/v1/analysis?project={p}&component={c}&vulnerability={v}`.

**Missing analysis.** When DT returns 404 or an empty body, the tool
returns the empty-analysis default (state `NOT_SET`, empty comments),
not null. Callers never have to null-check.

### 7.8 `find_duplicate_analyses`

**Input**
```
{
  "project_uuid": str,
  "component_uuid": str,
  "vulnerability_uuid": str
}
```

**Output**
```
{
  "target": {
    "project_uuid": str,
    "component": NormalizedComponent,
    "vulnerability": FindingVulnerabilitySummary,
    "analysis": NormalizedAnalysis
  },
  "aliases_in_project": [DuplicateEntry],
  "same_vuln_other_components": [DuplicateEntry],
  "other_projects": [DuplicateEntry + {"project": {uuid, name, version}}]
}
```

Where `DuplicateEntry` is `{component, vulnerability, analysis}` in the
same shape as `target` (minus `project_uuid`).

**Algorithm.**
1. Fetch the target project's findings (`suppressed=true` to include all).
2. Locate the target finding by `(component_uuid, vulnerability_uuid)`;
   raise `DTrackError` if missing.
3. Build `alias_keys = {(source, vuln_id)}` ∪ target's alias set.
4. For each other finding in the same project:
   - same `vulnerability.uuid` → `same_vuln_other_components`;
   - otherwise, alias-key intersection → `aliases_in_project`.
5. For each `(source, vuln_id)` in `alias_keys`:
   - `GET /api/v1/vulnerability/source/{s}/vuln/{id}/projects`
   - For each other project, fetch its findings and keep those whose
     alias keys intersect `alias_keys`.
6. For every duplicate found, call `get_analysis` so prior triage
   decisions are attached.

**Cost.** Worst case is `O(|alias_keys| × other_projects × findings)`.
In practice alias keys are 2–5 and the affected-project set is small.
Entries are deduplicated by `(project_uuid, component_uuid, vulnerability_uuid)`.

### 7.9 `set_analysis` (⚠ write)

**Input** (v0.7: `finding` added as an alternative to raw UUIDs — see §16.1)
```
{
  "project_uuid": str,                 // always required
  "component_uuid": str | null,        // required unless 'finding' is given
  "vulnerability_uuid": str | null,    // required unless 'finding' is given
  "finding": NormalizedFinding | null, // v0.7: accept a finding dict; UUIDs are extracted
  "state": str,                        // required, see AnalysisState enum
  "justification": str | null,         // CycloneDX enum, optional
  "response": str | null,              // CycloneDX enum, optional
  "details": str | null,               // free text, optional
  "comment": str | null,               // appended to history, optional
  "suppressed": bool | null            // optional
}
```

**Output:** `NormalizedAnalysis` (as returned by DT after the write).

**DT endpoint:** `PUT /api/v1/analysis`. Fields left as `null` are
omitted from the body so DT keeps its current value. `comment` appends
to the history, it does not replace it. `state` is validated client-side
against the `AnalysisState` enum before the request leaves the process.
(DT v4 records analysis decisions via PUT, not POST — whitelisting POST
once returned HTTP 405.)

**Guard.** Non-GET tool. Every other path lands in `_guard` and raises.
v0.2 adds a second write tool (`upload_bom`, see §11).

## 8. Errors

| Class | When | HTTP codes |
|---|---|---|
| `DTrackAuthError` | Bad creds, 401 after retry, 403 | 401, 403 |
| `DTrackHTTPError` | Any other non-2xx, `.status_code` + `.path` | 4xx (non-auth), 5xx |
| `DTrackError` | Config / usage errors (base class) | — |

MCP tool wrappers convert exceptions into `isError: true` results with a
message, preserving the exception class name.

## 9. Testing

- **Unit**: `normalize.py`, `alias.py` — mocked with real captured DT
  fixtures under `tests/fixtures/`.
- **Guard lock**: `tests/test_guard.py` exhaustively pins the
  `(method, path)` allowlist so any accidental expansion of write
  permissions fails CI.
- **Smoke** (`scripts/smoke.py`): runs against live DT with
  login+password from env. Exercises every read tool end-to-end on one
  real project. Safe to re-run.
- **No automated `set_analysis` against live DT.** The write path is
  only ever exercised by a human in the triage loop. CI never calls it.

## 10. Non-goals for Stage 1

- No caching layer
- No concurrency / parallel requests
- No OAuth 2.1 client auth on the MCP side (stdio only)
- No PyPI release
- No GitHub publication
- No Docker image

Stage 2 can add any of these once the tool proves itself in daily use.

## 11. Stage 3 (v0.2) — Version Lifecycle

Four tools that cover the release-cut flow: upload a new SBOM version,
discover existing versions of a project, compute a diff of findings
between two versions, and carry triage decisions forward. Full spec in
`DOCS/v0.2_spec.md`.

### 11.1 `upload_bom` (⚠ write)

**Input**
```
{
  "project_name": str,
  "project_version": str,
  "bom": str,                         // base64-encoded CycloneDX/SPDX
  "auto_create": bool,                // default false
  "parent_name": str | null,
  "parent_version": str | null
}
```

**Output:** `BomUploadResult` — `{token, project_uuid, message}`. Token
is the DT processing token; polling is a client responsibility (v0.2
deliberately does not ship a blocking `wait_bom_processed` helper —
blocking would break the stateless MCP contract).

**DT endpoint:** `POST /api/v1/bom` with JSON body. `bom` is validated
as base64 client-side before the request leaves the process.

### 11.2 `get_project_versions`

**Input:** `{name: str, active_only: bool = true}`.

**Output:** `ProjectVersionsResult` — `{name, total, versions:
list[NormalizedProject]}`, sorted by version desc (semver-aware with
lexicographic fallback).

### 11.3 `diff_findings`

Computes carried / updated_component / new / gone between two project
versions of the same product.

Matching uses `component_match_key(component) = (purl_type,
purl_namespace, purl_name)` — deliberately drops `purl_version` and
`purl_qualifiers` so DT 4.13→4.14 upgrades that add `distro=...` do
not mask every component as "new". Version is compared separately to
distinguish `exact_*` from `same_component_diff_version`.

Match priority: `exact_purl` > `exact_alias` > `same_component_diff_version`
> `alias_diff_component_version`.

`DiffResult.warnings[]` surfaces collisions where two source components
share a `component_match_key` but have distinct purls (multi-arch
SBOMs are the canonical case). The caller — human or LLM — must decide
whether the merge is safe.

### 11.4 `carry_over_triage` (⚠ write in `exact` mode)

**Input (selected):**
```
{
  "source_project_uuid": str,
  "target_project_uuid": str,
  "mode": "dry_run" | "exact",        // default "dry_run"
  "include_updated_components": bool, // default false
  "overwrite_not_set": bool,          // default true
  "overwrite_any": bool,              // default false
  "comment_prefix": str,              // default "[dtrack-mcp]"
  "max_operations": int               // default 500 — guard against LLM hallucination
}
```

**`dry_run` always runs first.** `exact` does writes only after a human
has approved the plan. If `len(candidates) > max_operations` in `exact`
mode, the call raises before any write — split the plan or raise the
cap explicitly.

Skip rules: source analysis is `NOT_SET`; target already has a
non-`NOT_SET` state and `overwrite_any=false`; target is `NOT_SET` and
`overwrite_not_set=false`.

Each transferred analysis gets a synthetic comment: `{prefix} Carried
from {source_project} {version}. Match: {reason}. Original comment:
{existing or (empty)}`.

`DTRACK_WRITE_DELAY_MS` (env, default 0) inserts a pause between writes
when DT is under load.

### 11.5 Version check on startup

`Connection` does a one-shot `GET /api/v1/version` on first successful
request. DT ≥ 4.14 → INFO log; older → WARNING (EPSS for GHSA and
CVSSv4 may be missing, distro qualifier matching degrades). Set
`DTRACK_SKIP_VERSION_CHECK=true` to disable (useful in offline tests).
Never raises — a missing endpoint is DEBUG-logged and the check is
marked done.

---

## 12. Stage 4 (v0.3) — Richer findings for single-call triage

**Motivation.** In the current triage loop `list_findings` and
`group_findings_by_alias` return `FindingVulnerabilitySummary` — a
compact subset that omits `description`, `title`, and `references`.
For every finding that needs a written verdict the LLM has to issue a
separate `get_vulnerability` call to read the description. On a project
with 100 `NOT_SET` findings this is 100 extra round trips, each
costing one JWT-authenticated HTTP request and adding latency.

The goal of v0.3 is to make a typical triage session work with **one
`list_findings` call** plus `set_analysis` writes, without needing
`get_vulnerability` for the common case.

### 12.1 Schema change — `FindingVulnerabilitySummary`

Add three fields to `FindingVulnerabilitySummary` (§6.5):

```
{
  ...existing fields...,
  "title":        str | null,      // NEW — short title from DT
  "description":  str | null,      // NEW — full description text
  "references":   [str]            // NEW — URLs extracted from DT markdown blob
}
```

These fields are already present in the raw DT finding response under
`vulnerability.title`, `vulnerability.description`, and
`vulnerability.references` — no extra HTTP request is needed.
`references` extraction reuses the existing regex from `normalize.py`.

**Size budget.** `description` can be 2–4 KB per finding. A project
with 500 findings would add ~1–2 MB to `list_findings` output —
violating the §3.3 response size target. Mitigation: add an opt-in
parameter `include_details: bool = false` to `list_findings` and
`group_findings_by_alias`. When `false` (default), the three new fields
are omitted and the payload stays compact. When `true`, they are
included. The LLM triage loop sets `include_details=true` for focused
batches (e.g. 20–30 findings at a time), not for full-project scans.

### 12.2 `list_findings` and `group_findings_by_alias` — new parameter

```
{
  ...existing params...,
  "include_details": bool = false   // NEW — include title/description/references
}
```

No other changes to these tools' contracts.

### 12.3 Impact on existing consumers

`FindingVulnerabilitySummary` gains three optional fields with
`include_details=false` default. Existing callers that do not pass
`include_details=true` see no change in output shape or size.
`get_vulnerability` remains the right tool for full vuln detail
(CVSS history, affected_components_count, complete alias graph) when
the finding summary is not enough.

### 12.4 Testing

- Unit: extend `test_normalize.py` — `normalize_finding` with
  `include_details=True` populates the three new fields; with
  `include_details=False` (default) they are absent.
- Smoke: add step 12 — call `list_findings(..., include_details=True)`
  on the sample project, assert at least one finding has non-null
  `description`.

### 12.5 Non-goals for v0.3

- No streaming / chunked response for large `description` blobs.
- No server-side truncation of `description` (caller's responsibility).
- No change to `get_vulnerability` — it remains the authoritative
  full-detail tool.

### 12.6 Deviation from the original sketch

The original §12.1 sketch called for the three new fields to be
*omitted* from the payload when `include_details=false`, which would
require `NotRequired` TypedDict keys (extra dep `typing_extensions` on
Python 3.10). Implementation deviates: the keys are **always present**
with `null` / `[]` defaults when details are off. Rationale:

- The dominant size concern (2–4 KB per `description` × 500 findings)
  is mitigated identically — the text itself is absent.
- Key-presence adds ≤ 50 bytes × finding, negligible against the
  §3.3 payload target.
- Stable keys keep the `FindingVulnerabilitySummary` shape
  `KeyError`-free for clients that don't branch on `include_details`.
- Matches the shape of `NormalizedVulnerability`, where these three
  fields are always present.

---

## 13. Stage 5 (v0.4) — Triage ergonomics

Ideas collected from live triage sessions.

### 13.0 v0.4 scope — signed off 2026-04-17

Five items ship in v0.4. The server-side size budget (§13.4.2) stays
out: the right threshold is unknown until compact mode (§13.4.1) and
state filtering (§13.3) run against real payloads, and a guessed cap
would break working calls. Revisit once residual overflow is measured.

| §     | Item                                      | v0.4 |
|-------|-------------------------------------------|------|
| 13.1  | `set_analysis_for_finding` wrapper (merged into `set_analysis` in v0.7 — see §16.1) | ✓    |
| 13.2  | `audit_ratio` on project metrics          | ✓    |
| 13.3  | `states` / `only_analyzed` filter         | ✓    |
| 13.4.1| `compact` mode on `find_duplicate_analyses` | ✓  |
| 13.4.2| Server-side size budget                   | —    |
| 13.5  | `active_only=True` / `project_tag`        | ✓    |


### 13.1 UUID verbosity in the triage loop

**Observation.** `set_analysis` and `find_duplicate_analyses` require
three UUIDs (`project_uuid`, `component_uuid`, `vulnerability_uuid`)
that the LLM must extract from a prior `list_findings` response and
pass verbatim. This is correct — DT's API is keyed by UUID — but it
makes each tool call long and error-prone when the LLM copies the wrong
UUID.

**Candidate mitigation.** No change to the API contract is needed: the
UUIDs are already in every `NormalizedFinding`. The friction is on the
LLM-usage side. Document in the `dtrack` skill that the canonical
pattern is:

```
finding = list_findings(...)[i]
set_analysis(
    project_uuid   = finding["component"]["uuid"],   # <-- wrong field
    ...
)
```

The real fix is in the skill prompt: spell out which UUID comes from
which field so the LLM does not have to infer it.

**Shipping in v0.4: `set_analysis_for_finding` wrapper.** Signature:

```
set_analysis_for_finding(
    project_uuid: str,          # kept explicit — finding in find_duplicate_analyses
                                # results may belong to a different project
    finding: NormalizedFinding, # extract component_uuid and vulnerability_uuid
    state: str,
    justification: str | None = None,
    response:      str | None = None,
    details:       str | None = None,
    comment:       str | None = None,
    suppressed:    bool | None = None,
) -> NormalizedAnalysis
```

Thin sugar over `set_analysis` — same write path (`PUT
/api/v1/analysis`), same guard, same validation. Raises `DTrackError`
if `finding["component"]["uuid"]` or `finding["vulnerability"]["uuid"]`
is missing. Does not touch the read-mostly invariant (§3.1).

### 13.2 Project triage coverage at a glance

**Observation.** There is no cheap way to answer "has this project been
triaged already?" without fetching all findings. `NormalizedProject`
carries `metrics.findings_audited` and `metrics.findings_unaudited`,
which partially answers the question, but the LLM has to call
`list_projects` or `lookup_project` and do the arithmetic itself.

**Candidate addition.** Expose a computed field `audit_ratio: float`
(= `findings_audited / findings_total`, or `null` when total is 0) in
`NormalizedProject.metrics`. Cost: trivial — one division in
`normalize_project`. Value: lets the LLM prioritise projects in a
triage queue without extra logic.

### 13.3 `find_duplicate_analyses`: filter by analysis state

**Observation.** `find_duplicate_analyses` currently returns every
finding of the same vulnerability across every project, regardless of
its analysis state. In a mature DT instance this is dominated by
`NOT_SET` noise: for CVE-2025-69421 (openssl PKCS#12) a single call
produced ~108 KB of JSON, of which only a handful of entries carried
an actual `NOT_AFFECTED`/`EXPLOITABLE` verdict that the triager could
reuse. The result overflowed the MCP inline-token budget, was auto-
spooled to a file, and had to be post-filtered with external tooling
(Bash + `python -c 'json.load(...)'`) — a workflow the user explicitly
pushed back on ("why are you using Bash instead of the MCP server").

**Candidate mitigation.** Add a server-side filter:

```
find_duplicate_analyses(
    ...,
    states: list[Literal["NOT_SET","NOT_AFFECTED","EXPLOITABLE",
                          "FALSE_POSITIVE","RESOLVED","IN_TRIAGE"]] | None = None,
    only_analyzed: bool = False,   # shorthand for states=all-except-NOT_SET
)
```

Default stays backward-compatible (no filter). In the skill, the
canonical triage call becomes `only_analyzed=true`: the LLM only cares
about *prior verdicts*, not about the list of other projects that are
also untriaged.

**Precedence when both are set.** `states` is the full knob and wins:
if `states` is non-empty, `only_analyzed` is ignored (even if true).
Rationale: `only_analyzed=true` is just shorthand for `states =
["EXPLOITABLE","FALSE_POSITIVE","NOT_AFFECTED","RESOLVED","IN_TRIAGE"]`,
so an explicit list is always more specific. Documented in the tool
docstring.

**Filter scope.** All three output buckets are filtered
(`aliases_in_project`, `same_vuln_other_components`, `other_projects`).
The `target` entry itself is never filtered — the caller identified it
by uuid and expects it back.

**Implementation.** Post-filter on the MCP client side: DT already
returns the analysis state inside each finding payload; we just skip
entries whose state does not match. No API change on the DT side.

### 13.4 Overflow guard on MCP results

**Observation.** Several tools (`find_duplicate_analyses`,
`list_findings` with large projects, `group_findings_by_alias`) can
return payloads that exceed the inline token budget. The current
behaviour is: the runtime spools the raw JSON to a tool-results file
and instructs the LLM to read it in chunks or use `jq`. In practice
that means dropping to Bash and hand-parsing — exactly what we want to
avoid.

**Candidate mitigation (two layers).**

1. **Compact mode on `find_duplicate_analyses`** — `compact: bool =
   False`. When `True`, the listed keys are dropped (set to `null` /
   `[]` / `""`) before serialization. No inference by string length —
   the field list is fixed and testable.

   | Path                              | Compact action                   |
   |-----------------------------------|----------------------------------|
   | `vulnerability.title`             | set to `null`                    |
   | `vulnerability.description`       | set to `null`                    |
   | `vulnerability.references`        | set to `[]`                      |
   | `vulnerability.cvss_v3_vector`    | set to `null` (keep `cvss_v3_score`) |
   | `vulnerability.cvss_v4_vector`    | set to `null` (keep `cvss_v4_score`) |
   | `component.purl_qualifiers`       | set to `{}` (distro=/arch= blobs)|
   | `component.latest_version`        | set to `null`                    |
   | `analysis.details`                | set to `null`                    |
   | `analysis.comments[*].comment`    | truncate to 200 chars + `"..."`  |

   What stays: `vulnerability.{uuid,source,vuln_id,severity,
   cvss_*_score,cwes,epss_score,in_kev,aliases}`, `component.{uuid,
   name,version,group,purl,purl_type,purl_namespace,purl_name,
   purl_version}`, `analysis.{state,justification,response,
   is_suppressed,comments[*].{commenter,timestamp}}`. Comment bodies
   keep a 200-char preview so the triager can still see what a prior
   analyst wrote, without paying 5–50 KB per paragraph.

   Applied to all three output buckets and to `target`. Default off,
   existing callers see no change. The `dtrack` skill flips it on by
   default.

2. **Server-side size budget.** Deferred to a later release — see
   §13.0. The correct cap is unknown until real payloads under
   compact+states filtering stabilise.

### 13.5 `find_duplicate_analyses`: scope to "actionable" by default

**Observation.** Even with state filtering (§13.3), the result still
includes analyses from *inactive* or *archived* projects, which are
rarely useful as a reuse source. A triager reusing a verdict wants
"what did someone else on an active, related project decide?", not
"what was set once in 2023 on a now-archived POC".

**Candidate mitigation.** Add `active_only: bool = True` (default
flipped!) and optional `project_tag: str | None` to narrow the scope
to projects matching a tag (e.g. `arenadata-release`). Both parameters
map cleanly to DT's existing project flags.

### 13.6 Priority / rollout

v0.4 ships §13.1, §13.2, §13.3, §13.4.1, §13.5 together. §13.4.2
stays out — see §13.0. Implementation order:

1. **§13.2 audit_ratio** — one field in `ProjectMetrics`; zero risk.
2. **§13.1 set_analysis_for_finding** — thin wrapper; no new write path.
3. **§13.3 states / only_analyzed** — post-filter in the three buckets
   of `find_duplicate_analyses`.
4. **§13.4.1 compact** — same tool, fixed field list above, single
   post-processor.
5. **§13.5 active_only / project_tag** — same tool, client-side filter
   on the `other_projects` loop.

Only §13.5 flips a default (`active_only: bool = True`). Every other
change is default-off or additive. `find_duplicate_analyses` callers
that never pass the new flags lose archived-project entries — the only
behavioural delta — which is the point.

---

## 14. Stage 5 (v0.4.1 patch) — `get_project` by UUID

**Problem.** When the user passes a raw project UUID (e.g. copied from
the DT UI URL), there is no tool that resolves it to a project record.
`lookup_project` requires name + version; `list_projects` dumps every
project (144 KB for ~500 entries) and forces the LLM to post-filter
with jq — an anti-pattern.

**Fix.** Add one thin tool:

```
get_project(project_uuid: str) → NormalizedProject | null
```

Calls `GET /api/v1/project/{uuid}` — a single DT endpoint that returns
exactly one project object. Response normalised to the same
`NormalizedProject` shape used by `list_projects` and `lookup_project`.
Returns `null` (not an error) when DT responds 404; re-raises other
HTTP errors.

**Scope.** Read-only. No new data model — reuses existing
`NormalizedProject`. No size risk (single object). Ships as an additive
patch on top of v0.4 (version bump 0.4.0 → 0.4.1); mirrors
`lookup_project` one-for-one, just swapping the DT endpoint.

---

## 15. Stage 6 — Strict Input Validation (v0.5)

### Problem

**Unknown parameters are silently ignored.** When an LLM caller passes a
parameter that does not exist in a tool's signature, the MCP framework
(or Pydantic with `extra='ignore'`) drops it without any error or
warning. The tool executes as if the parameter were never provided — its
default value kicks in, and the result is silently wrong.

**Concrete incident (2026-04-17):** `group_findings_by_alias` was called
with `only_not_set=True`. That parameter does not exist; the correct
parameter is `analysis_states=["NOT_SET"]`. The call succeeded, returned
18 groups (all non-suppressed findings), and the triage loop treated all
18 as requiring analysis — 15 of which were already EXPLOITABLE and
needed nothing.

**Why this is dangerous for an LLM caller specifically:**
- An LLM constructs tool calls from in-context descriptions (tool
  docstrings, prior examples, session memory). Parameter names drift
  between versions, and the LLM's memory of them can be stale.
- A human caller reading a stack trace immediately sees `TypeError:
  unexpected keyword argument`. An LLM sees a successful call and a
  plausible-looking response — there is no signal that the filter was
  ignored.
- The silent failure produces **misleading data at scale**: the loop
  queued 15 spurious items that had already been triaged, wasting time
  and risking overwriting correct EXPLOITABLE entries with NOT_AFFECTED.

This class of bug is not caught by the guard tests (§9) because those
pin HTTP methods and paths, not input schemas.

### Root cause

The MCP tool functions are decorated with `@mcp.tool()`. The framework
deserialises the JSON call arguments into Python kwargs. If Pydantic
models are used with `model_config = ConfigDict(extra='ignore')`, or if
the framework simply passes only recognised kwargs, unknown parameters
are silently dropped. No exception is raised.

### Fix (three layers)

**Layer 1 — Function-level: reject unexpected kwargs.**
Every MCP tool wrapper that accepts `**kwargs` must raise on unknown keys.
For tools with explicit signatures (no `**kwargs`): the framework itself
must be configured to raise on unknown params, not ignore them.

Implementation option A (if the framework supports it): set
`extra='forbid'` in the Pydantic input model for each tool. This raises
`ValidationError` before the function body executes.

Implementation option B (manual guard, framework-agnostic): add to the
top of every tool wrapper:

```python
def _check_no_extra(known: set[str], actual: dict) -> None:
    extra = set(actual) - known
    if extra:
        raise TypeError(f"Unexpected parameters: {sorted(extra)}")
```

Call it as the first statement in the wrapper, passing the set of
documented param names and the raw kwargs dict (before binding).

**Layer 2 — Enum / literal validation for string parameters.**
Parameters like `analysis_states`, `severities`, `mode`, `state`,
`justification` accept only a fixed set of strings. Unknown values
currently reach the DT API where they may be silently dropped or cause
opaque 4xx errors.

Fix: declare each as `Literal[...]` or an `Enum`, and validate before
the HTTP call. Validation error must be explicit:
`ValueError("analysis_states: unknown value 'NOT_SET_TYPO'; allowed: ...")`.

Known string-enum parameters to cover:
- `analysis_states` in `list_findings`, `group_findings_by_alias`,
  `find_duplicate_analyses` — values: `NOT_SET`, `IN_TRIAGE`,
  `EXPLOITABLE`, `FALSE_POSITIVE`, `NOT_AFFECTED`, `RESOLVED`
- `severities` — values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`,
  `UNASSIGNED`
- `state` in `set_analysis`, `set_analysis_for_finding` — same set as
  `analysis_states`
- `justification` — CycloneDX enum values
- `response` — CycloneDX enum values
- `mode` in `carry_over_triage` — values: `dry_run`, `exact`

**Layer 3 — Convenience alias for the most common filter pattern.**
The most frequent caller mistake is `only_not_set=True` instead of
`analysis_states=["NOT_SET"]`. Add an explicit convenience parameter:

```python
def group_findings_by_alias(
    project_uuid: str,
    suppressed: bool = False,
    analysis_states: list[AnalysisState] | None = None,
    only_not_set: bool = False,   # ← new, convenience alias
    ...
)
```

Semantics: `only_not_set=True` is equivalent to
`analysis_states=["NOT_SET"]`. If both are provided and conflict, raise
`ValueError`. Document this alias prominently in the docstring.

Apply the same pattern to `list_findings`.

### Test coverage required

- Unit test: calling any tool with an unknown kwarg raises `TypeError`
  (not silently succeeds).
- Unit test: calling with an out-of-range enum value raises `ValueError`
  with the allowed set in the message.
- Unit test: `only_not_set=True` produces the same result as
  `analysis_states=["NOT_SET"]`.
- Unit test: `only_not_set=True` + `analysis_states=[...]` raises
  `ValueError`.

### Scope

All tools in the MCP server, not just `group_findings_by_alias`. The
principle is: **every parameter must be validated before use; unknown
parameters must be rejected with an explicit error message.** Silent
pass-through of unrecognised input is never acceptable in a tool whose
output drives automated triage decisions.

---

## 16. Stage 7 (v0.7) — Tool Consolidation & Cross-Project Search

### 16.0 Motivation

v0.6 shipped with 16 tools. LLMs degrade at tool selection when the
count exceeds ~12. Several tools had overlapping responsibilities, and
a key workflow — "which projects are affected by CVE-X?" — required
manual iteration. v0.7 consolidates redundant tools and adds one new
read-only tool.

### 16.1 Tool merges (16 → 14)

| Before (v0.6) | After (v0.7) | Change |
|---|---|---|
| `lookup_project` + `get_project` | `resolve_project` | UUID or name+version in one tool |
| `get_vulnerability` + `find_vulnerability` | `find_vulnerability` | Optional `source` param; probes when omitted |
| `set_analysis` + `set_analysis_for_finding` | `set_analysis` | Optional `finding` param; extracts UUIDs when provided |

**`resolve_project`** — `project_uuid` takes precedence when provided;
`name` + `version` used otherwise. At least one path must be given.
Internal functions `_lookup_project` and `_get_project` remain for use
by `upload_bom`, `broadcast_triage`, and `diff_findings`.

**`find_vulnerability`** — new `source: str | None` parameter. When
given, fetches directly from that namespace. When omitted, infers
candidate sources from the id prefix and probes. Returns `None` on 404
regardless of path. Internal `_get_vulnerability` remains for direct
callers that want a raising semantic.

**`set_analysis`** — new `finding: dict | None` parameter. When given,
`component_uuid` and `vulnerability_uuid` are extracted from it;
explicit UUIDs are still accepted for callers that have them.
`project_uuid` remains required in all paths.

### 16.2 New tool: `search_vulnerability`

```
search_vulnerability(
    vuln_id: str,
    active_only: bool = True,
    only_analyzed: bool = False,
) -> {vulnerability, affected_projects, total_projects} | null
```

Resolves the vulnerability via `find_vulnerability`, then queries DT
for every project containing it (via the
`/vulnerability/source/{s}/vuln/{id}/projects` endpoint). For each
project, fetches findings matching the alias cluster and returns a
per-component analysis summary. Read-only, no new write path.

### 16.3 Removed: `only_not_set` convenience parameter

The v0.5 `only_not_set` convenience alias for
`analysis_states=["NOT_SET"]` was never implemented as a real
parameter — the validation layer (`seal_schemas` +
`additionalProperties: false`) already rejects it. Removed from the
spec; the SPEC §15 Layer 3 section is superseded.

### 16.4 Removed: `include_raw`

The `include_raw: bool` parameter described in SPEC §7 was never
implemented. Debug output is covered by `DTRACK_LOG_LEVEL=DEBUG`.
Removed from the spec.

### 16.5 Test coverage

210 tests (was 199). New tests cover:
- `resolve_project`: UUID path, name+version path, UUID precedence,
  missing params error, name-without-version error
- `find_vulnerability` with explicit `source`: direct fetch, 404
  handling
- `search_vulnerability`: not-found returns null, found returns
  projects with analysis state
- `set_analysis` with `finding`: UUID extraction, optional field
  forwarding, missing UUID errors, missing both params error

---

## 17. Stage 8 (v0.7.1 patch) — Rate-limit / transient-failure retry

### Problem

`Connection` had no retry layer. A single HTTP 429 (throttling), 503
(backend restart, GC), or transport-level error (connection refused
during deploy, read timeout under load) surfaced to the tool as
`DTrackHTTPError` / `httpx.TransportError`. For bulk write tools
(`carry_over_triage`, `broadcast_triage`) this meant a run of hundreds
of `PUT /api/v1/analysis` calls could abort midway with no way to tell
which entries landed — the `DTRACK_WRITE_DELAY_MS` knob mitigates but
does not remove the window.

### Fix

`Connection._send_with_retry` wraps the underlying `_send` with an
exponential-backoff retry loop. It sits **between** the auth-retry
layer (which owns 401 → re-login) and the raw HTTP call (which owns
the `_guard` allowlist). Non-invasive: no public API change, no new
tool, no change to the guard's allowlist.

### Retry policy

| Condition | Retried? |
|---|---|
| HTTP 429 Too Many Requests | Yes |
| HTTP 502 / 503 / 504 | Yes |
| `httpx.TransportError` (ConnectError, ReadTimeout, etc.) | Yes |
| HTTP 401 | No — auth-retry layer owns it |
| Any other 4xx (400, 403, 404, 405, 409, 422, …) | No — caller bug |
| HTTP 500 | No — not a transient failure signal; caller bug or DT bug |
| `_guard` `RuntimeError` | No — raised before send, never retried |

**Backoff.** `base * 2^attempt + uniform(0, base)` seconds, where `base
= DTRACK_RETRY_BACKOFF_MS / 1000`. Jitter is there so two clients that
hit the same 503 don't synchronise on retry. With defaults (base=0.5 s,
max=3 retries) the maximum wait is `0.5 + 1 + 2 + 4 ≈ 7.5 s` across
attempts 1–4 before the final failure surfaces.

**`Retry-After` header.** Honoured when numeric (`Retry-After: 30`);
capped at 60 s so a misconfigured DT cannot freeze a client forever.
HTTP-date form is ignored (falls back to exponential backoff) — DT
never emits it in practice.

**Config.** `DTRACK_RETRY_MAX` (default 3, set to 0 to disable),
`DTRACK_RETRY_BACKOFF_MS` (default 500). Per-connection, read at
`DTrackConfig.from_env` time.

### Integration-tested against the lab

Verified against a local DT 4.14.1 docker-compose stand. The recovery
probe in `scripts/smoke_retry.py` stopped the apiserver container for
~12 s mid-loop; `Connection` survived with 4 retries (backoff
1 → 2.2 → 3.5 → 6.5 s) and 0 client-visible failures over 18
subsequent requests.

### Test coverage

23 new unit tests in `tests/test_retry.py`:

- Happy path (no retry when 200)
- Each retryable status (429, 502, 503, 504) → success on second try
- Retry exhaustion raises `DTrackHTTPError` with the last status code
- Each non-retryable status (400, 404, 405, 409, 422, 500) → no retry
- 401 propagates to auth-retry layer, not consumed by rate-limit layer
- `Retry-After` numeric respected; capped at 60 s; non-numeric falls back
- `httpx.TransportError` retried and exhausted correctly
- `_guard` refusals never retried
- Exponential backoff grows as `base * 2^attempt` (with jitter bounds)
- `DTRACK_RETRY_MAX=0` disables retries
- `from_env` reads both knobs with correct defaults

### Scope — what retry does NOT do

- **No idempotency key.** `PUT /api/v1/analysis` is idempotent for
  `state/justification/response/details/suppressed` (same input →
  same state). The `comment` field appends to history, so a retry
  after a partial success can double-post. Mitigated by existing
  carry_over skip-rules (`overwrite_any=false`) seeing the already-
  set state on the re-run and skipping. Full idempotency would need
  a server-side op-id, out of scope here.
- **No circuit breaker.** If DT is down for minutes, every call waits
  its full backoff budget then fails. Acceptable: dtrack-mcp is a
  per-session CLI, not a long-lived service.
- **No per-tool override.** Retry config is connection-wide. A bulk
  `carry_over_triage` that wants aggressive retry uses the same knobs
  as a single `list_projects`.
