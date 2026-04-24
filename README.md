# dtrack-mcp

MCP server that connects Claude (or any MCP-compatible LLM) to [Dependency-Track](https://dependencytrack.org/).

Instead of clicking through the DT UI to triage hundreds of vulnerability findings, describe what you need in natural language — Claude pulls the data, reasons over it, and writes the verdict back.

---

## Why

Dependency-Track accumulates findings fast. A product with 5 versions and 100+ vulnerabilities each means 500+ rows to triage — each requiring you to open a finding, read the CVE, check CVSS, look at EPSS/KEV signals, see what other projects decided, and pick a state. That's hours of browser clicking per release cycle.

dtrack-mcp exposes DT as an MCP server so Claude can do the data work:

- Pull findings filtered by severity or state
- Deduplicate CVE/GHSA/OSV aliases into one group per real issue
- Check what was decided for the same vulnerability in other projects or versions
- Write the triage decision back to DT with a comment

---

## Key scenarios

**1. Triage a batch of findings**
```
Show me all CRITICAL and HIGH findings in project "myapp v2.3.0"
that haven't been analysed yet. Group by alias so I don't see
the same CVE twice. For each group tell me the CVSS vector,
EPSS score, and whether it's in CISA KEV.
```

**2. Carry triage forward when upgrading**
```
We just uploaded the SBOM for myapp v2.4.0. Carry over all
triage decisions from v2.3.0 — dry run first, then apply.
```

**3. Propagate a decision across versions**

A new CVE is found in v1.0, v1.1, v2.0, and v2.1 simultaneously.
Triage it in one version, then carry the decision backward and forward
to the others:
```
Set CVE-2024-12345 in myapp v2.1.0 as NOT_AFFECTED
(justification: CODE_NOT_REACHABLE). Then carry that decision
to v1.0, v1.1, and v2.0.
```

---

## Tools

| Tool | Description |
|---|---|
| `list_projects` | List projects with vulnerability counts |
| `resolve_project` | Find project by UUID or by exact name + version |
| `list_findings` | Findings with severity / state / suppressed filters |
| `group_findings_by_alias` | Deduplicate CVE/GHSA/OSV via union-find |
| `find_vulnerability` | Full detail by id, optionally specifying source |
| `search_vulnerability` | Which projects are affected by a given CVE? |
| `get_analysis` | Current triage state + full comment history |
| `find_duplicate_analyses` | Same vuln in other components / projects, with prior analyses |
| `set_analysis` | ⚠ WRITE — set state, justification, response, comment. Accepts raw UUIDs or a finding dict |
| `get_project_versions` | All versions of a project, newest first |
| `diff_findings` | Carried / updated / new / gone between two versions |
| `carry_over_triage` | ⚠ WRITE — transfer decisions v1 → v2 (or v2 → v1) |
| `broadcast_triage` | ⚠ WRITE — fan out one decision to all versions of a project |
| `upload_bom` | ⚠ WRITE — upload CycloneDX/SPDX SBOM |

All tools are read-only except the four marked ⚠ WRITE. The HTTP layer
enforces this: any write path other than `PUT /api/v1/analysis` and
`POST /api/v1/bom` raises before reaching the network.

---

## Requirements

- **Python 3.10+** (tested on 3.10–3.12).
- **Dependency-Track 4.11+**. DT 4.14+ is recommended — earlier versions
  lack EPSS-for-GHSA data and CVSSv4 fields, and purl distro-qualifier
  matching degrades. The server logs a warning at startup when it
  detects an older DT.
- **An MCP-capable client** — Claude Desktop, Claude Code, or any other
  stdio MCP runtime.
- A DT account with `VIEW_PORTFOLIO` + `VULNERABILITY_ANALYSIS`
  permissions (and `BOM_UPLOAD` if you use `upload_bom`).

Linux and macOS are the primary targets; Windows works under WSL.

## Installation

```bash
# Replace with the repository URL once it is published.
git clone <REPO_URL> dtrack-mcp
cd dtrack-mcp
pip install -e .
```

After `pip install`, the `dtrack-mcp` command is on `$PATH` and starts
the MCP server on stdio. A quick local smoke test against your DT
instance:

```bash
DTRACK_URL=https://dt.example.com \
DTRACK_API_KEY=odt_... \
python scripts/smoke.py
```

`scripts/smoke.py` is read-only and safe to re-run — it exercises every
GET-based tool on one real project and prints a compact summary.

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "dtrack": {
      "command": "dtrack-mcp",
      "env": {
        "DTRACK_URL": "https://dt.example.com",
        "DTRACK_API_KEY": "odt_..."
      }
    }
  }
}
```

**Claude Code** — add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "dtrack": {
      "command": "dtrack-mcp",
      "env": {
        "DTRACK_URL": "https://dt.example.com",
        "DTRACK_API_KEY": "odt_..."
      }
    }
  }
}
```

Restart Claude after editing the config.

### Auth options

| Variable | Description |
|---|---|
| `DTRACK_URL` | Base URL of your DT instance |
| `DTRACK_API_KEY` | Preferred. Requires VIEW_PORTFOLIO + VULNERABILITY_ANALYSIS permissions. Add BOM_UPLOAD for `upload_bom`. |
| `DTRACK_USER` + `DTRACK_PASSWORD` | Alternative. Exchanges credentials for a JWT; re-fetches on 401. |

### Optional tuning

| Variable | Default | Description |
|---|---|---|
| `DTRACK_TIMEOUT` | `30` | HTTP timeout in seconds. |
| `DTRACK_VERIFY_TLS` | `false` | Set `true` when your DT instance has a certificate your system trust store recognises. |
| `DTRACK_RETRY_MAX` | `3` | Retries on HTTP 429/502/503/504 and transport errors (connect refused, read timeout). `0` disables retries. |
| `DTRACK_RETRY_BACKOFF_MS` | `500` | Base for exponential backoff: `base · 2^attempt + jitter`. `Retry-After` header is honoured up to a 60 s cap. |
| `DTRACK_WRITE_DELAY_MS` | `0` | Sleep between writes in `carry_over_triage` / `broadcast_triage`. Use when DT is under load. |
| `DTRACK_LOG_LEVEL` | `INFO` | Standard `logging` level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). Logs go to stderr. |
| `DTRACK_SKIP_VERSION_CHECK` | `false` | Skip the one-shot `GET /api/v1/version` probe at first request. Useful for offline or heavily-mocked tests. |

Proxies are disabled inside the client (`trust_env=False`) because DT
is typically on an internal network and corporate proxies refuse to
tunnel it. Equivalent to `curl --noproxy '*'`.

---

## Safety

- **Read-mostly by design.** Writes are gated at the HTTP client level, not in application logic. The guard runs before any network call. The only allowed write paths are `PUT /api/v1/analysis` (triage) and `POST /api/v1/bom` (SBOM upload).
- **Input validation.** All tool parameters are validated against enum allowlists before hitting DT. Unknown parameters are rejected (`additionalProperties: false` in JSON schema).
- **`carry_over_triage` and `broadcast_triage` default to `dry_run`.** No writes happen unless you explicitly pass `mode="exact"` after reviewing the plan.
- **`max_operations` cap.** Bulk write operations fail early if the plan exceeds 500 entries by default, preventing accidental mass-triage from a hallucinated call.
- **Transient-failure retry.** Connection refuseds, read timeouts, and HTTP 429/502/503/504 are retried with exponential backoff (see `DTRACK_RETRY_*`); no other status is retried, so a broken caller never loops.
- **No secrets in logs.** Credentials come from env only; JWTs and API keys are never logged, and raw DT responses are never echoed verbatim into tool output.

---

## Troubleshooting

- **`no credentials: set DTRACK_API_KEY or DTRACK_USER+DTRACK_PASSWORD`** at startup — the env is not visible to the MCP subprocess. Put the vars in the `env` block of your client config (examples above), not just in your shell.
- **`DTRACK_URL is not set`** — same cause as above.
- **`HTTP 401` after `api_key` auth** — the key was revoked or lacks the required permissions. API-key auth does not re-login; rotate the key in DT and update the client config.
- **`HTTP 403 on PUT /api/v1/analysis`** — your account lacks `VULNERABILITY_ANALYSIS`. Read-only tools work without it.
- **`dtrack-mcp: refused <METHOD> <path>`** — you hit the read-mostly guard. Either the call is outside the documented write allowlist (which is the whole point of the guard) or DT introduced a new endpoint and the spec needs updating — open an issue, don't relax the guard locally.
- **Every call is slow on login+password auth** — the JWT is cached per-process, so this only happens at startup. If it repeats, the client is restarting between calls; prefer `DTRACK_API_KEY` for long sessions.

---

## Documentation

- [`SPEC.md`](SPEC.md) — full protocol specification: normalized schemas,
  per-tool input/output contracts, hard invariants, per-stage evolution.
- [`scripts/smoke.py`](scripts/smoke.py) — end-to-end read-only smoke
  test; mirrors the shape of a real triage session.
- [`scripts/smoke_retry.py`](scripts/smoke_retry.py) — retry-layer
  integration check; includes a recovery-probe mode that requires a
  live DT instance you can restart.

---

## License

MIT — see [`LICENSE`](LICENSE).
