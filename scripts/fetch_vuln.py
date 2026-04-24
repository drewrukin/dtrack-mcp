"""Fetch one vulnerability by id and print the normalized JSON.

Reads DTRACK_* from /home/user/1_Arenadata/AI/ENV/tokens.env (bash-style,
parsed in Python — file contains backticks that break `source`).

Usage (from repo root):
    .venv/bin/python scripts/fetch_vuln.py CVE-2026-33034
    .venv/bin/python scripts/fetch_vuln.py --source NVD CVE-2026-33034
"""

from __future__ import annotations

import json
import os
import sys

ENV_FILE = "/home/user/1_Arenadata/AI/ENV/tokens.env"


def _load_env() -> None:
    if not os.path.exists(ENV_FILE):
        return
    for raw in open(ENV_FILE):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        os.environ.setdefault(k.strip(), v)


_load_env()

from dtrack_mcp import api  # noqa: E402
from dtrack_mcp.connection import Connection, DTrackConfig  # noqa: E402


def main() -> int:
    args = sys.argv[1:]
    source: str | None = None
    if args and args[0] == "--source":
        if len(args) < 3:
            print("usage: fetch_vuln.py [--source SOURCE] <VULN_ID>", file=sys.stderr)
            return 2
        source, vuln_id = args[1], args[2]
    elif len(args) == 1:
        vuln_id = args[0]
    else:
        print("usage: fetch_vuln.py [--source SOURCE] <VULN_ID>", file=sys.stderr)
        return 2

    with Connection(DTrackConfig.from_env()) as conn:
        if source:
            vuln = api.get_vulnerability(conn, source=source, vuln_id=vuln_id)
        else:
            vuln = api.find_vulnerability(conn, vuln_id=vuln_id)
    if vuln is None:
        print(f"not found: {vuln_id}", file=sys.stderr)
        return 1
    print(json.dumps(vuln, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
