#!/usr/bin/env bash
# Restore DT lab to the frozen baseline snapshot.
# Run before each test session to get a clean slate.
# Usage: ./reset-lab.sh
#
# What it does:
#   1. Stops the DT apiserver (keeps postgres running)
#   2. Drops and recreates the dtrack database
#   3. Restores from baseline.pgdump
#   4. Starts apiserver back up
#   5. Verifies findings count matches baseline

set -euo pipefail

COMPOSE_DIR="${COMPOSE_DIR:-/home/andrew/dtrack-lab}"
DUMP="$COMPOSE_DIR/baseline.pgdump"

# Source lab/.env (never committed; see .gitignore) for LAB_URL / LAB_API_KEY.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
fi
: "${LAB_URL:?LAB_URL must be set (export it or put it in lab/.env)}"
: "${LAB_API_KEY:?LAB_API_KEY must be set (export it or put it in lab/.env)}"

if [[ ! -f "$DUMP" ]]; then
    echo "ERROR: $DUMP not found. Run this on fortify or copy dump first." >&2
    exit 1
fi

echo "=== Resetting DT lab to baseline ==="

echo "[1/5] Stopping apiserver..."
ssh fortify "cd $COMPOSE_DIR && docker compose stop apiserver"

echo "[2/5] Dropping and recreating database..."
ssh fortify "docker exec dtrack-lab-postgres-1 psql -U dtrack -c 'DROP DATABASE IF EXISTS dtrack;'"
ssh fortify "docker exec dtrack-lab-postgres-1 psql -U dtrack -c 'CREATE DATABASE dtrack OWNER dtrack;'"

echo "[3/5] Restoring from baseline.pgdump..."
ssh fortify "docker exec -i dtrack-lab-postgres-1 pg_restore -U dtrack -d dtrack < $DUMP"

echo "[4/5] Starting apiserver..."
ssh fortify "cd $COMPOSE_DIR && docker compose start apiserver"

echo "[4/5] Waiting for apiserver to be ready..."
for i in $(seq 1 30); do
    STATUS=$(curl -s --noproxy '*' -o /dev/null -w "%{http_code}" "$LAB_URL/api/v1/version" 2>/dev/null || echo "000")
    if [[ "$STATUS" == "200" ]]; then
        echo "  apiserver ready after ${i}s"
        break
    fi
    sleep 2
done

echo "[5/5] Verifying findings count..."
COUNT=$(curl -s --noproxy '*' -H "X-Api-Key: $LAB_API_KEY" "$LAB_URL/api/v1/finding?limit=1" -D - -o /dev/null 2>/dev/null | grep "X-Total-Count" | awk '{print $2}' | tr -d '\r')
echo "  findings: $COUNT"

echo "=== Reset complete ==="
