"""Smoke test for the retry layer against the lab DT instance.

Two phases:
  1. Baseline burst — 20 consecutive GETs against /api/version. No DT
     downtime. Confirms the retry layer did not regress happy path.
  2. Recovery — runs GET in a tight loop for N seconds. While the loop
     is running, the operator stops the DT apiserver container for a
     few seconds from another terminal. The loop must survive, with
     retry-backoff bridging the gap.

Env: DTRACK_URL, DTRACK_API_KEY, DTRACK_RETRY_MAX (default 5 here),
DTRACK_RETRY_BACKOFF_MS (default 500). Retry config is deliberately
bumped vs production defaults so a ~10 s downtime is survivable.

Recovery-phase instruction — the operator triggers apiserver downtime
from another terminal. For a local docker-compose stand that looks like:

  ssh <lab-host> "cd <compose-dir> && docker compose stop apiserver && sleep 6 && docker compose start apiserver"

Run:
  DTRACK_URL=https://dt.example.com \\
  DTRACK_API_KEY=odt_... \\
  DTRACK_RETRY_MAX=6 DTRACK_RETRY_BACKOFF_MS=800 \\
  DTRACK_SKIP_VERSION_CHECK=true \\
  python scripts/smoke_retry.py
"""

from __future__ import annotations

import logging
import os
import sys
import time

from dtrack_mcp.connection import Connection, DTrackConfig


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )


def baseline_burst(conn: Connection, n: int = 20) -> None:
    print(f"\n=== baseline burst: {n} × GET /api/version ===")
    t0 = time.monotonic()
    for i in range(n):
        resp = conn.get("/api/version")
        version = resp.get("version") if isinstance(resp, dict) else "?"
        print(f"  [{i + 1:02d}/{n}] ok  version={version}")
    elapsed = time.monotonic() - t0
    print(f"baseline: {n} requests in {elapsed:.2f}s "
          f"(avg {elapsed / n * 1000:.1f}ms)")


def recovery_probe(conn: Connection, duration_s: int = 40) -> None:
    print(f"\n=== recovery probe: {duration_s}s loop, 1 req/s ===")
    print("STOP the apiserver from another terminal now, then START it.")
    print("Suggested (adapt to your lab host / compose dir):")
    print("  ssh <lab-host> 'cd <compose-dir> && docker compose stop apiserver "
          "&& sleep 6 && docker compose start apiserver'")
    t0 = time.monotonic()
    ok = 0
    failed = 0
    last_err: str | None = None
    while time.monotonic() - t0 < duration_s:
        try:
            conn.get("/api/version")
            ok += 1
            print(f"  t={time.monotonic() - t0:5.1f}s  ok")
        except Exception as exc:  # noqa: BLE001 — smoke script: surface every failure mode
            failed += 1
            last_err = f"{type(exc).__name__}: {exc}"
            print(f"  t={time.monotonic() - t0:5.1f}s  FAIL {last_err}")
        time.sleep(1.0)
    print(f"\nrecovery: ok={ok}  failed={failed}  last_err={last_err}")


def main() -> int:
    _setup_logging()
    config = DTrackConfig.from_env()
    print(f"dtrack: {config.base_url}  "
          f"retry_max={config.retry_max}  "
          f"backoff_ms={config.retry_backoff_ms}")

    with Connection(config) as conn:
        baseline_burst(conn, n=20)
        if os.environ.get("DTRACK_SKIP_RECOVERY", "").lower() == "true":
            print("\n(recovery probe skipped via DTRACK_SKIP_RECOVERY)")
            return 0
        duration = int(os.environ.get("DTRACK_RECOVERY_SECONDS", "40"))
        recovery_probe(conn, duration_s=duration)
    return 0


if __name__ == "__main__":
    sys.exit(main())
