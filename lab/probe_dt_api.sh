#!/usr/bin/env bash
# DT API probe — determines how DT responds to invalid input.
# Used to verify enum values and error behaviour for the @validated decorator.
# Usage: ./probe_dt_api.sh
# Requires: lab/.env with LAB_URL and LAB_API_KEY

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

_read_var() { grep -m1 "^${1}=" "$ENV_FILE" | cut -d= -f2-; }
LAB_URL="${LAB_URL:-$(_read_var LAB_URL)}"
LAB_API_KEY="${LAB_API_KEY:-$(_read_var LAB_API_KEY)}"

BASE="${LAB_URL%/}"
CURL=(curl -s --noproxy '*' -w "\nHTTP:%{http_code}")
AUTH=(-H "X-Api-Key: $LAB_API_KEY")

# Need a project UUID that has findings to probe PUT /analysis
PROJECT_UUID=$(curl -sf --noproxy '*' "$BASE/api/v1/project?pageSize=1" \
    -H "X-Api-Key: $LAB_API_KEY" \
    | python3 -c "import sys,json; ps=json.load(sys.stdin); print(ps[0]['uuid']) if ps else print('')" 2>/dev/null || echo "")

# Fetch the first finding in that project
FINDING=""
if [[ -n "$PROJECT_UUID" ]]; then
    FINDING=$(curl -sf --noproxy '*' "$BASE/api/v1/finding/project/$PROJECT_UUID?limit=1" \
        -H "X-Api-Key: $LAB_API_KEY" \
        | python3 -c "
import sys,json
d=json.load(sys.stdin)
findings=d.get('findings', d) if isinstance(d, dict) else d
if findings:
    f=findings[0]
    print(f['component']['uuid'] + ' ' + f['vulnerability']['uuid'])
" 2>/dev/null || echo "")
fi

COMP_UUID=$(echo "$FINDING" | cut -d' ' -f1)
VULN_UUID=$(echo "$FINDING" | cut -d' ' -f2)

echo "=== DT API Probe — $BASE ==="
echo "Project: $PROJECT_UUID"
echo "Component: $COMP_UUID / Vuln: $VULN_UUID"
echo ""

probe() {
    local DESC="$1"; shift
    echo -n "[$DESC] "
    RESP=$("${CURL[@]}" "$@" 2>/dev/null || true)
    HTTP=$(echo "$RESP" | grep -o 'HTTP:[0-9]*' | cut -d: -f2 || echo "000")
    BODY=$(echo "$RESP" | grep -v '^HTTP:' || true)
    BODY="${BODY:0:200}"
    echo "HTTP $HTTP | $BODY"
}

echo "--- 1. Unknown query param (GET /finding/project) ---"
probe "unknown param onlyNotSet=true" "${AUTH[@]}" \
    "$BASE/api/v1/finding/project/$PROJECT_UUID?onlyNotSet=true&limit=5"
probe "unknown param fooBar=baz" "${AUTH[@]}" \
    "$BASE/api/v1/finding/project/$PROJECT_UUID?fooBar=baz&limit=5"

echo ""
echo "--- 2. Invalid enum in query (analysisStates) ---"
probe "invalid analysisStates=NOT_SET_TYPO" "${AUTH[@]}" \
    "$BASE/api/v1/finding/project/$PROJECT_UUID?analysisStates=NOT_SET_TYPO"
probe "valid analysisStates=NOT_SET" "${AUTH[@]}" \
    "$BASE/api/v1/finding/project/$PROJECT_UUID?analysisStates=NOT_SET&limit=3"

echo ""
echo "--- 3. PUT /analysis — unknown JSON field ---"
if [[ -n "$COMP_UUID" && -n "$VULN_UUID" ]]; then
    probe "unknown field unknownField" "${AUTH[@]}" -X PUT "$BASE/api/v1/analysis" \
        -H "Content-Type: application/json" \
        -d "{\"project\":\"$PROJECT_UUID\",\"component\":\"$COMP_UUID\",\"vulnerability\":\"$VULN_UUID\",\"analysisState\":\"IN_TRIAGE\",\"unknownField\":\"test\"}"
    probe "valid PUT IN_TRIAGE" "${AUTH[@]}" -X PUT "$BASE/api/v1/analysis" \
        -H "Content-Type: application/json" \
        -d "{\"project\":\"$PROJECT_UUID\",\"component\":\"$COMP_UUID\",\"vulnerability\":\"$VULN_UUID\",\"analysisState\":\"IN_TRIAGE\"}"
else
    echo "  SKIP: no findings yet (DT still processing BOM)"
fi

echo ""
echo "--- 4. PUT /analysis — invalid enum in JSON body ---"
if [[ -n "$COMP_UUID" && -n "$VULN_UUID" ]]; then
    probe "invalid analysisState=NOT_SET_TYPO" "${AUTH[@]}" -X PUT "$BASE/api/v1/analysis" \
        -H "Content-Type: application/json" \
        -d "{\"project\":\"$PROJECT_UUID\",\"component\":\"$COMP_UUID\",\"vulnerability\":\"$VULN_UUID\",\"analysisState\":\"NOT_SET_TYPO\"}"
    probe "invalid justification=MADE_UP" "${AUTH[@]}" -X PUT "$BASE/api/v1/analysis" \
        -H "Content-Type: application/json" \
        -d "{\"project\":\"$PROJECT_UUID\",\"component\":\"$COMP_UUID\",\"vulnerability\":\"$VULN_UUID\",\"analysisState\":\"NOT_AFFECTED\",\"analysisJustification\":\"MADE_UP\"}"
else
    echo "  SKIP: no findings yet"
fi

echo ""
echo "--- 5. PUT /analysis — missing required fields ---"
probe "missing vulnerability" "${AUTH[@]}" -X PUT "$BASE/api/v1/analysis" \
    -H "Content-Type: application/json" \
    -d "{\"project\":\"$PROJECT_UUID\",\"component\":\"$COMP_UUID\",\"analysisState\":\"IN_TRIAGE\"}"
probe "empty body" "${AUTH[@]}" -X PUT "$BASE/api/v1/analysis" \
    -H "Content-Type: application/json" \
    -d "{}"

echo ""
echo "=== Probe complete ==="
