#!/usr/bin/env bash
# Import fixtures into lab DT instance.
# Usage: ./bootstrap.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
ENV_FILE="$SCRIPT_DIR/.env"

_read_var() { grep -m1 "^${1}=" "$ENV_FILE" | cut -d= -f2-; }
LAB_URL="${LAB_URL:-$(_read_var LAB_URL)}"
LAB_API_KEY="${LAB_API_KEY:-$(_read_var LAB_API_KEY)}"

: "${LAB_URL:?LAB_URL not set}"
: "${LAB_API_KEY:?LAB_API_KEY not set}"

BASE="${LAB_URL%/}"
CURL=(curl -sf --noproxy '*')
AUTH=(-H "X-Api-Key: $LAB_API_KEY")
TMP=$(mktemp)
trap "rm -f $TMP" EXIT

echo "=== Bootstrap DT lab: $BASE ==="
echo ""

for META_FILE in "$FIXTURES_DIR"/*.meta.json; do
    UUID=$(basename "$META_FILE" .meta.json)
    BOM_FILE="$FIXTURES_DIR/${UUID}.bom.json"
    VEX_FILE="$FIXTURES_DIR/${UUID}.vex.json"

    NAME=$(python3 -c "import json; p=json.load(open('$META_FILE')); print(p.get('name','?'))")
    VER=$(python3 -c "import json; p=json.load(open('$META_FILE')); print(p.get('version','') or '')")
    IS_LATEST=$(python3 -c "import json; p=json.load(open('$META_FILE')); print(str(p.get('isLatest', False)).lower())")
    echo "--- $NAME $VER ---"

    # Build BOM payload into tempfile
    python3 -c "
import json, base64
bom_b64 = base64.b64encode(open('$BOM_FILE', 'rb').read()).decode()
print(json.dumps({'projectName': '$NAME', 'projectVersion': '$VER', 'autoCreate': True, 'bom': bom_b64}))
" > "$TMP"

    RESP=$("${CURL[@]}" "${AUTH[@]}" -X PUT "$BASE/api/v1/bom" \
        -H "Content-Type: application/json" -d @"$TMP")
    TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','?'))" 2>/dev/null || echo "?")
    echo "  BOM uploaded, token: $TOKEN"

    # Wait for BOM processing (up to 60s)
    for i in $(seq 1 12); do
        PROCESSING=$("${CURL[@]}" "${AUTH[@]}" "$BASE/api/v1/bom/token/$TOKEN" \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('processing', True))" 2>/dev/null || echo "true")
        if [[ "$PROCESSING" == "False" || "$PROCESSING" == "false" ]]; then break; fi
        sleep 5
    done

    # Find project UUID in lab
    NAME_ENC=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$NAME")
    VER_ENC=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$VER")
    LAB_UUID=$("${CURL[@]}" "${AUTH[@]}" "$BASE/api/v1/project/lookup?name=$NAME_ENC&version=$VER_ENC" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['uuid'])" 2>/dev/null || echo "")

    if [[ -z "$LAB_UUID" ]]; then
        echo "  WARNING: project not found after BOM upload, skipping VEX"
        continue
    fi
    echo "  Lab UUID: $LAB_UUID"

    # Set isLatest from meta
    "${CURL[@]}" "${AUTH[@]}" -X PATCH "$BASE/api/v1/project/$LAB_UUID" \
        -H "Content-Type: application/json" \
        -d "{\"isLatest\": $IS_LATEST}" -o /dev/null
    echo "  isLatest: $IS_LATEST"

    # Build VEX payload into tempfile
    python3 -c "
import json, base64
vex_b64 = base64.b64encode(open('$VEX_FILE', 'rb').read()).decode()
print(json.dumps({'project': '$LAB_UUID', 'vex': vex_b64}))
" > "$TMP"

    "${CURL[@]}" "${AUTH[@]}" -X PUT "$BASE/api/v1/vex" \
        -H "Content-Type: application/json" -d @"$TMP" -o /dev/null
    echo "  VEX uploaded"
done

echo ""
echo "=== Tagging spark projects ==="
for NAME_PAT in "adb-spark3-connector" "adb-spark4-connector"; do
    UUIDS=$("${CURL[@]}" "${AUTH[@]}" "$BASE/api/v1/project?name=$NAME_PAT&pageSize=10" \
        | python3 -c "import sys,json; [print(p['uuid']) for p in json.load(sys.stdin)]" 2>/dev/null || echo "")
    for U in $UUIDS; do
        "${CURL[@]}" "${AUTH[@]}" -X PATCH "$BASE/api/v1/project/$U" \
            -H "Content-Type: application/json" \
            -d '{"tags": [{"name": "spark"}]}' -o /dev/null
        echo "  Tagged $U → spark"
    done
done

echo ""
echo "=== Bootstrap complete ==="
"${CURL[@]}" "${AUTH[@]}" "$BASE/api/v1/project?pageSize=200" \
    | python3 -c "
import sys, json
ps = json.load(sys.stdin)
print(f'Projects in lab: {len(ps)}')
for p in ps:
    f = p.get('metrics', {}).get('findings_total', 0)
    a = p.get('metrics', {}).get('findings_audited', 0)
    print(f'  {p[\"name\"]} {p.get(\"version\",\"\")} — {f} findings, {a} audited')
"
