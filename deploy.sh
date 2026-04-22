#!/usr/bin/env bash
# deploy.sh -- push to main, stream live CI steps, then smoke-test the live site.
set -euo pipefail

REPO="elevate-foundry/speculative-agent"
SITE="https://elevate-foundry.github.io/speculative-agent/"
TIMEOUT=180
POLL=8

# -- 1. Push ------------------------------------------------------------------
echo "> Pushing to main..."
git push origin main

# -- 2. Find the run ID for this commit ---------------------------------------
COMMIT=$(git rev-parse HEAD)
echo "> Waiting for CI run for commit ${COMMIT:0:8}..."

RUN_ID=""
for i in $(seq 1 10); do
  RUN_ID=$(gh run list --repo "$REPO" --branch main --limit 5 --json headSha,databaseId,status \
    | python3 -c "
import json,sys
runs=json.load(sys.stdin)
for r in runs:
    if r['headSha']=='$COMMIT':
        print(r['databaseId']); break
" 2>/dev/null || true)
  [[ -n "$RUN_ID" ]] && break
  sleep 3
done

if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: Could not find CI run. Check: https://github.com/$REPO/actions"
  exit 1
fi

echo "> Run $RUN_ID -> https://github.com/$REPO/actions/runs/$RUN_ID"
echo "> Streaming steps..."
echo ""

# -- 3. Stream live step status -----------------------------------------------
LAST_COUNT=0
ELAPSED=0
while true; do
  STEPS=$(gh run view "$RUN_ID" --repo "$REPO" --json jobs 2>/dev/null \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
lines = []
for job in data.get('jobs', []):
    for step in job.get('steps', []):
        status = step.get('status','')
        conclusion = step.get('conclusion') or ''
        name = step.get('name','')
        if status == 'in_progress':
            icon = '\033[34m~\033[0m'
        elif conclusion == 'success':
            icon = '\033[32mv\033[0m'
        elif conclusion in ('failure','cancelled','timed_out'):
            icon = '\033[31mx\033[0m'
        else:
            icon = ' '
        lines.append(f'  {icon}  {name}')
print('\n'.join(lines))
" 2>/dev/null || true)

  STEP_COUNT=$(echo "$STEPS" | wc -l)
  if [[ $LAST_COUNT -gt 0 ]]; then
    printf "\033[%dA" "$LAST_COUNT"
  fi
  echo "$STEPS"
  LAST_COUNT=$STEP_COUNT

  RESULT=$(gh run view "$RUN_ID" --repo "$REPO" --json status,conclusion \
    | python3 -c "import json,sys; r=json.load(sys.stdin); print(r['status'],r.get('conclusion',''))")
  STATUS=$(echo "$RESULT" | awk '{print $1}')
  CONCLUSION=$(echo "$RESULT" | awk '{print $2}')

  if [[ "$STATUS" == "completed" ]]; then
    echo ""
    if [[ "$CONCLUSION" == "success" ]]; then
      echo "CI passed in ${ELAPSED}s"
      break
    else
      echo "FAIL: CI $CONCLUSION"
      gh run view "$RUN_ID" --repo "$REPO" --log-failed 2>/dev/null | tail -50 || true
      exit 1
    fi
  fi

  sleep $POLL
  ELAPSED=$((ELAPSED + POLL))
  [[ $ELAPSED -ge $TIMEOUT ]] && { echo "FAIL: timed out"; exit 1; }
done

# -- 4. Smoke-test ------------------------------------------------------------
echo "> Smoke-testing live site..."
sleep 5

check() {
  local label="$1" url="$2"
  local code
  code=$(curl -sI "$url" | head -1 | awk '{print $2}')
  if [[ "$code" == "200" ]]; then
    echo "  OK  $url"
  else
    echo "  !!  $url  (HTTP $code)"
  fi
}

check "site"    "$SITE"
check "favicon" "${SITE}favicon.svg"
check "eval"    "${SITE}eval/"

echo ""
echo "Live: $SITE"
