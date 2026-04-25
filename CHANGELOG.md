# Changelog

All notable changes to **dtrack-mcp** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1] — 2026-04-25

Initial public release.

### MCP tools (14 total)

**Read**

- `list_projects` — projects with vulnerability counts
- `resolve_project` — find project by UUID or by exact name + version
- `list_findings` — findings with severity / state / suppressed filters; `include_details` returns full vulnerability + analysis context
- `group_findings_by_alias` — union-find dedup across CVE / GHSA / OSV / Snyk / NVD
- `find_vulnerability` — full detail by id, optionally specifying source
- `search_vulnerability` — which projects are affected by a given CVE
- `get_analysis` — current triage state + full comment history
- `find_duplicate_analyses` — same vulnerability seen elsewhere (alias / component / cross-project) with prior analyses
- `get_project_versions` — all versions of a project, newest first
- `diff_findings` — `carried` / `updated_component` / `new` / `gone` between two versions

**Write** (gated at the HTTP client level)

- `set_analysis` — set state, justification, response, comment; accepts raw UUIDs or a finding dict
- `carry_over_triage` — transfer decisions v1 → v2 (or v2 → v1); defaults to `dry_run`
- `broadcast_triage` — fan a single decision across all versions of a project; defaults to `dry_run`
- `upload_bom` — upload CycloneDX / SPDX SBOM

### Safety

- Read-mostly by design. Allowed write paths: `PUT /api/v1/analysis`, `POST /api/v1/bom`. Anything else is refused before the network call.
- Strict input validation: all tool parameters are validated against enum allowlists; unknown parameters are rejected (`additionalProperties: false`).
- Bulk-write tools default to `dry_run` and cap operations at 500 by default.
- Transient failures (HTTP 429 / 502 / 503 / 504, connect refused, read timeout) are retried with exponential backoff and `Retry-After` honoured; nothing else is retried.
- Credentials are env-only and never logged.

### Compatibility

- Python 3.10–3.12.
- Dependency-Track 4.11+; 4.14+ recommended (earlier DT versions lack EPSS-for-GHSA and CVSSv4 fields).

[0.7.1]: https://github.com/drewrukin/dtrack-mcp/releases/tag/v0.7.1
