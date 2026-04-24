#!/usr/bin/env bash
# Freeze all DT vulnerability feed updates and re-analysis.
# Run BEFORE a test session to prevent findings from changing mid-test.
# Usage: ./freeze-feeds.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

_read_var() { [[ -f "$ENV_FILE" ]] && grep -m1 "^${1}=" "$ENV_FILE" | cut -d= -f2- || true; }
LAB_URL="${LAB_URL:-$(_read_var LAB_URL)}"
LAB_ADMIN_PASSWORD="${LAB_ADMIN_PASSWORD:-$(_read_var LAB_ADMIN_PASSWORD)}"
: "${LAB_URL:?LAB_URL must be set (export it or put it in lab/.env)}"
: "${LAB_ADMIN_PASSWORD:?LAB_ADMIN_PASSWORD must be set (export it or put it in lab/.env)}"

BASE="${LAB_URL%/}"
CURL=(curl -sf --noproxy '*')

TOKEN=$("${CURL[@]}" -X POST "$BASE/api/v1/user/login" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=$LAB_ADMIN_PASSWORD")
AUTH=(-H "Authorization: Bearer $TOKEN")

FREEZE=999999  # hours (~114 years)

echo "=== Freezing DT feeds ($BASE) ==="
"${CURL[@]}" "${AUTH[@]}" -X POST "$BASE/api/v1/configProperty/aggregate" \
    -H "Content-Type: application/json" \
    -d "[
      {\"groupName\":\"task-scheduler\",\"propertyName\":\"nist.mirror.cadence\",\"propertyValue\":\"$FREEZE\",\"propertyType\":\"INTEGER\"},
      {\"groupName\":\"task-scheduler\",\"propertyName\":\"ghsa.mirror.cadence\",\"propertyValue\":\"$FREEZE\",\"propertyType\":\"INTEGER\"},
      {\"groupName\":\"task-scheduler\",\"propertyName\":\"osv.mirror.cadence\",\"propertyValue\":\"$FREEZE\",\"propertyType\":\"INTEGER\"},
      {\"groupName\":\"task-scheduler\",\"propertyName\":\"vulndb.mirror.cadence\",\"propertyValue\":\"$FREEZE\",\"propertyType\":\"INTEGER\"},
      {\"groupName\":\"task-scheduler\",\"propertyName\":\"portfolio.vulnerability.analysis.cadence\",\"propertyValue\":\"$FREEZE\",\"propertyType\":\"INTEGER\"},
      {\"groupName\":\"task-scheduler\",\"propertyName\":\"repository.metadata.fetch.cadence\",\"propertyValue\":\"$FREEZE\",\"propertyType\":\"INTEGER\"}
    ]" | python3 -c "
import json, sys
for x in json.load(sys.stdin):
    if isinstance(x, dict):
        print(f'  OK  {x[\"groupName\"]}/{x[\"propertyName\"]} = {x[\"propertyValue\"]}')
    else:
        print(f'  ERR {x}', file=sys.stderr)
"
echo "Feeds frozen. Findings will not change until unfreeze-feeds.sh is run."
