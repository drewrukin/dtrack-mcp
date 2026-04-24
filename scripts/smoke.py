"""End-to-end smoke test against a live Dependency-Track instance.

READ-ONLY. Uses only the GET-based API functions; does not modify DT
state in any way.

Reads credentials from env (DTRACK_URL, DTRACK_USER, DTRACK_PASSWORD or
DTRACK_API_KEY). Exits non-zero on any failure so it can be used as a
health check.
"""

from __future__ import annotations

import json
import sys

from dtrack_mcp import api
from dtrack_mcp.connection import Connection, DTrackConfig


def _heading(text: str) -> None:
    print(f"\n=== {text} ===")


def _short(obj: object, limit: int = 400) -> str:
    s = json.dumps(obj, ensure_ascii=False, default=str)
    return s if len(s) <= limit else s[:limit] + f"... [+{len(s) - limit}]"


def main() -> int:
    config = DTrackConfig.from_env()
    print(
        f"dtrack: {config.base_url}  auth="
        f"{'api_key' if config.has_api_key() else 'login'}"
    )

    with Connection(config) as conn:
        _heading("1. version")
        version = conn.get("/api/version")
        print(_short(version))

        _heading("2. list_projects (page 1, size 10)")
        listing = api.list_projects(conn, page=1, page_size=10)
        print(f"total on this page: {listing['total']}")
        for p in listing["items"][:3]:
            print(
                f"  {p['uuid'][:8]} {p['name']} {p['version']} "
                f"vulns={p['metrics']['vulnerabilities']}"
            )

        _heading("3. list_projects with name_filter='adh-jmx'")
        filtered = api.list_projects(conn, name_filter="adh-jmx", page_size=5)
        print(f"found: {filtered['total']}")
        if not filtered["items"]:
            print("ABORT: no adh-jmx-exporter project to smoke-test findings on")
            return 1
        target = filtered["items"][0]
        print(f"target: {target['name']} {target['version']} uuid={target['uuid']}")

        _heading("4. lookup_project(exact)")
        one = api.lookup_project(
            conn, name=target["name"], version=target["version"] or ""
        )
        assert one is not None, "lookup_project returned None for known project"
        print(f"lookup_project ok: {one['uuid'] == target['uuid']}")

        _heading("4b. get_project(uuid) / 404 path (v0.4.1)")
        by_uuid = api.get_project(conn, project_uuid=target["uuid"])
        assert by_uuid is not None and by_uuid["uuid"] == target["uuid"]
        missing = api.get_project(conn, project_uuid="00000000-0000-0000-0000-000000000000")
        assert missing is None, "get_project should return None on 404"
        print("get_project ok: resolved by uuid, missing uuid → None")

        _heading("5. list_findings")
        findings = api.list_findings(
            conn, project_uuid=target["uuid"], page_size=20
        )
        print(f"total findings: {findings['total']}")
        for f in findings["items"][:3]:
            v = f["vulnerability"]
            print(
                f"  {v['severity']:9} {v['source']:7} {v['vuln_id']:30} "
                f"on {f['component']['name']}@{f['component']['version']} "
                f"cvss_v3={v['cvss_v3_score']} cvss_v4={v['cvss_v4_score']}"
            )

        _heading("6. list_findings severities=['MEDIUM','HIGH','CRITICAL']")
        high_only = api.list_findings(
            conn,
            project_uuid=target["uuid"],
            severities=["MEDIUM", "HIGH", "CRITICAL"],
            page_size=50,
        )
        print(f"after filter: {high_only['total']} (was {findings['total']})")

        _heading("7. group_findings_by_alias")
        groups = api.group_findings_by_alias(
            conn, project_uuid=target["uuid"], page_size=10
        )
        print(
            f"groups={groups['total_groups']} "
            f"findings={groups['total_findings']}"
        )
        for g in groups["groups"][:3]:
            cid = g["canonical_id"]
            aliases = ", ".join(
                f"{a['source']}/{a['vuln_id']}" for a in g["aliases"]
            )
            print(
                f"  canonical={cid['source']}/{cid['vuln_id']}  "
                f"members={len(g['findings'])}  aliases=[{aliases}]"
            )
            if g["merge_reason"]:
                print(f"    merge_reason: {g['merge_reason']}")

        _heading("8. find_vulnerability by id (no source hint)")
        if findings["items"]:
            sample = findings["items"][0]["vulnerability"]
            found = api.find_vulnerability(conn, vuln_id=sample["vuln_id"])
            if found is None:
                print(f"  {sample['vuln_id']} not found (unexpected)")
                return 1
            print(
                f"  {sample['vuln_id']} -> source={found['source']} "
                f"severity={found['severity']} epss={found['epss_score']}"
            )

        _heading("9. get_vulnerability full detail")
        if findings["items"]:
            sample = findings["items"][0]["vulnerability"]
            v = api.get_vulnerability(
                conn, source=sample["source"], vuln_id=sample["vuln_id"]
            )
            print(
                f"  title: {v['title'][:80] if v['title'] else None}"
            )
            print(f"  cvss_v4={v['cvss_v4_score']} cvss_v3={v['cvss_v3_score']}")
            print(f"  cwes={v['cwes']}  refs={len(v['references'])}")
            print(f"  aliases: {[(a['source'], a['vuln_id']) for a in v['aliases']]}")

        _heading("10. get_project_versions (v0.2)")
        versions = api.get_project_versions(conn, name=target["name"])
        print(f"versions of {target['name']}: {versions['total']}")
        for p in versions["versions"][:5]:
            print(
                f"  {p['version']:20} uuid={p['uuid'][:8]} "
                f"active={p['active']} latest={p['is_latest']}"
            )

        _heading("11. diff_findings (v0.2, read-only)")
        if versions["total"] >= 2:
            src_p = versions["versions"][1]  # older
            tgt_p = versions["versions"][0]  # newer
            diff = api.diff_findings(
                conn,
                source_project_uuid=src_p["uuid"],
                target_project_uuid=tgt_p["uuid"],
                include_analysis=False,
            )
            print(
                f"  {src_p['version']} → {tgt_p['version']}: "
                f"carried={diff['stats']['carried']} "
                f"updated={diff['stats']['updated_component']} "
                f"new={diff['stats']['new']} gone={diff['stats']['gone']}"
            )
            if diff["warnings"]:
                print(f"  warnings: {len(diff['warnings'])} "
                      f"(first: {diff['warnings'][0][:120]})")
        else:
            print("  skipped: need ≥2 versions of the same project")

        _heading("12. list_findings(include_details=True) (v0.3)")
        detailed = api.list_findings(
            conn,
            project_uuid=target["uuid"],
            page_size=20,
            include_details=True,
        )
        with_desc = [
            f for f in detailed["items"]
            if f["vulnerability"].get("description")
        ]
        print(
            f"  findings on page: {len(detailed['items'])}  "
            f"with description: {len(with_desc)}"
        )
        if with_desc:
            v = with_desc[0]["vulnerability"]
            title = (v.get("title") or "")[:80]
            desc_len = len(v.get("description") or "")
            refs = len(v.get("references") or [])
            print(
                f"  sample: {v['vuln_id']} title={title!r} "
                f"desc_len={desc_len} refs={refs}"
            )
        elif detailed["items"]:
            print("  no findings on this page carry a description")

        _heading("13. audit_ratio (v0.4)")
        print(
            f"  {target['name']} {target['version']}: "
            f"audit_ratio={target['metrics']['audit_ratio']} "
            f"(audited={target['metrics']['findings_audited']}/"
            f"total={target['metrics']['findings_total']})"
        )

        _heading("14. find_duplicate_analyses(only_analyzed, compact) (v0.4)")
        if findings["items"]:
            f0 = findings["items"][0]
            dup = api.find_duplicate_analyses(
                conn,
                project_uuid=target["uuid"],
                component_uuid=f0["component"]["uuid"],
                vulnerability_uuid=f0["vulnerability"]["uuid"],
                only_analyzed=True,
                compact=True,
            )
            print(
                f"  target={f0['vulnerability']['vuln_id']}  "
                f"aliases_in_project={len(dup['aliases_in_project'])}  "
                f"same_vuln_other_components={len(dup['same_vuln_other_components'])}  "
                f"other_projects={len(dup['other_projects'])}"
            )
            # Verify compact really dropped bulky fields on target.
            tv = dup["target"]["vulnerability"]
            assert tv["description"] is None and tv["references"] == []
            print("  compact: description / references dropped on target ✓")

    print("\nall smoke checks passed ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
