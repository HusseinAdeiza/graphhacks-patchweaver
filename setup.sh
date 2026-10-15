#!/usr/bin/env bash
# setup.sh — one command to run PatchWeaver end-to-end.
#
# Prerequisites: Docker (for FalkorDB) and Node.js 18+. Nothing else.
# This script starts FalkorDB, installs deps, seeds the graph, optionally pulls
# LIVE OSV advisories, then runs the agent and prints the verdict.

set -euo pipefail
cd "$(dirname "$0")"

FALKOR_PORT="${FALKOR_PORT:-6381}"
CONTAINER="patchweaver-falkordb"

echo "==> [1/6] Starting FalkorDB (graph database) on port $FALKOR_PORT"
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  docker start "$CONTAINER" >/dev/null
else
  docker run -d --name "$CONTAINER" -p "${FALKOR_PORT}:6379" falkordb/falkordb:latest >/dev/null
fi
# wait for it to accept connections
for i in $(seq 1 30); do
  if (echo > /dev/tcp/127.0.0.1/$FALKOR_PORT) >/dev/null 2>&1; then break; fi
  sleep 0.5
done
echo "    FalkorDB ready."

echo "==> [2/6] Installing Node dependencies"
npm install --no-audit --no-fund >/dev/null

echo "==> [3/6] Seeding the demo dependency graph (deterministic reset)"
node graph/load.js

if [ "${SKIP_OSV:-0}" = "1" ]; then
  echo "==> [4/6] SKIP_OSV=1 — using seeded demo advisories only"
else
  echo "==> [4/6] Pulling LIVE advisories from OSV for lodash, qs, minimist"
  node graph/osv.js "lodash,qs,minimist" || echo "    (OSV unreachable — continuing with demo advisories)"
fi

echo "==> [5/6] Running the PatchWeaver agent (OBSERVE -> PLAN -> ACT -> VERIFY)"
node agent/act.js .

echo "==> [6/6] Verifying (standalone check with exit code)"
node verify.js

echo ""
echo "Done. Patched manifest written to package.patched.json"
echo "  plan only : node planner/plan.js"
echo "  Cypher    : cypher/queries.cypher"
