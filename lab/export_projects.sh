#!/usr/bin/env bash
# Export BOM + VEX for selected projects from prod DT.
# Usage: ./export_projects.sh [UUID...]
# Without args: lists all projects so you can pick UUIDs.
#
# Credentials: DTRACK_URL / DTRACK_USER / DTRACK_PASSWORD from env or tokens.env.
# Output: lab/fixtures/{uuid}.bom.json + {uuid}.vex.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKENS_ENV="$(dirname "$SCRIPT_DIR")/../ENV/tokens.env"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

# Load tokens if not already in env (safe: avoids shell-parsing special chars)
_read_var() { grep -m1 "^${1}=" "$TOKENS_ENV" | cut -d= -f2-; }
if [[ -f "$TOKENS_ENV" ]]; then
    DTRACK_URL="${DTRACK_URL:-$(_read_var DTRACK_URL)}"
    DTRACK_USER="${DTRACK_USER:-$(_read_var DTRACK_USER)}"
    DTRACK_PASSWORD="${DTRACK_PASSWORD:-$(_read_var DTRACK_PASSWORD)}"
fi

: "${DTRACK_URL:?DTRACK_URL not set}"
: "${DTRACK_USER:?DTRACK_USER not set}"
: "${DTRACK_PASSWORD:?DTRACK_PASSWORD not set}"

BASE="${DTRACK_URL%/}"
CURL=(curl -sf --noproxy '*')

# --- auth ---
echo "Authenticating as $DTRACK_USER ..."
TOKEN=$("${CURL[@]}" -X POST "$BASE/api/v1/user/login" \
    --data-urlencode "username=${DTRACK_USER}" \
    --data-urlencode "password=${DTRACK_PASSWORD}")

if [[ -z "$TOKEN" ]]; then
    echo "ERROR: empty token — check credentials" >&2
    exit 1
fi
echo "OK"

AUTH=(-H "Authorization: Bearer $TOKEN")

# --- list mode ---
if [[ $# -eq 0 ]]; then
    echo ""
    echo "No UUIDs given. Projects in prod DT (name | version | uuid):"
    echo "------------------------------------------------------------"
    "${CURL[@]}" "${AUTH[@]}" "$BASE/api/v1/project?pageSize=200&sortName=name&sortOrder=asc" \
        | python3 -c "
import sys, json
projects = json.load(sys.stdin)
for p in projects:
    print(f\"{p.get('name','?'):<50} {p.get('version',''):<20} {p['uuid']}\")
"
    echo ""
    echo "Re-run with UUIDs to export:  ./export_projects.sh UUID1 UUID2 ..."
    exit 0
fi

# --- export mode ---
mkdir -p "$FIXTURES_DIR"

for UUID in "$@"; do
    echo ""
    echo "Exporting $UUID ..."

    # Project metadata (for filename hint)
    META=$("${CURL[@]}" "${AUTH[@]}" "$BASE/api/v1/project/$UUID" || echo '{}')
    NAME=$(echo "$META" | python3 -c "import sys,json; p=json.load(sys.stdin); print(p.get('name','unknown').replace('/','_'))" 2>/dev/null || echo "unknown")
    VER=$(echo "$META" | python3 -c "import sys,json; p=json.load(sys.stdin); print(p.get('version','').replace('/','_'))" 2>/dev/null || echo "")
    LABEL="${NAME}${VER:+_$VER}"

    BOM_FILE="$FIXTURES_DIR/${UUID}.bom.json"
    VEX_FILE="$FIXTURES_DIR/${UUID}.vex.json"
    META_FILE="$FIXTURES_DIR/${UUID}.meta.json"

    # BOM (CycloneDX JSON)
    "${CURL[@]}" "${AUTH[@]}" "$BASE/api/v1/bom/cyclonedx/project/$UUID?format=JSON&variant=withVulnerabilities&download=false" \
        -o "$BOM_FILE"
    echo "  BOM → $BOM_FILE  ($LABEL)"

    # VEX (CycloneDX JSON) — analysis states + verdicts
    "${CURL[@]}" "${AUTH[@]}" "$BASE/api/v1/vex/cyclonedx/project/$UUID?format=JSON&download=false" \
        -o "$VEX_FILE"
    echo "  VEX → $VEX_FILE"

    # Meta — name/version/tags for bootstrap reference
    echo "$META" > "$META_FILE"
    echo "  META → $META_FILE"
done

echo ""
echo "Done. Fixtures in $FIXTURES_DIR"
echo "Next: pick projects, run lab/import_projects.sh against the lab DT instance."
