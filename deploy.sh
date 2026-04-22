#!/usr/bin/env bash
# deploy.sh — push to main, wait for GitHub Pages deploy to complete, then smoke-test the live URL.
set -euo pipefail

REPO="elevate-foundry/speculative-agent"
SITE="https://elevate-foundry.github.io/speculative-agent/"
TIMEOUT=180   # seconds before we give up
POLL=8        # seconds between status checks

# ── 1. Push ──────────────────────────────────────────────────────────────────
echo "▶ Pushing to main…"
git push origin main

# ── 2. Get the run ID for the commit we just pushed ──────────────────────────
COMMIT=$(git rev-parse HEAD)
echo "▶ Waiting for CI run for commit ${COMMIT:0:8}…"

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
  echo "✗ Could not find CI run for this commit. Check: https://github.com/$REPO/actions"
  exit 1
fi

echo "▶ Run ID: $RUN_ID  →  https://github.com/$REPO/actions/runs/$RUN_ID"

# ── 3. Stream live log output ─────────────────────────────────────────────────
echo "▶ Streaming CI log…"
echo ""

LAST_STEP=""
ELAPSED=0
while true; do
  # Fetch job steps with their status
  STEPS=$(gh run view "$RUN_ID" --repo "$REPO" --json jobs 2>/dev/null \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
for job in data.get('jobs', []):
    for step in job.get('steps', []):
        status = step.get('status','')
        conclusion = step.get('conclusion') or ''
        name = step.get('name','')
        if status == 'in_progress':
            icon = '\033[34m⟳\033[0m'
        elif conclusion == 'success':
            icon = '\033[32m✓\033[0m'
        elif conclusion in ('failure','cancelled'):
            icon = '\033[31m✗\033[0m'
        else:
            icon = ' '
        print(f'{icon} {name}')
" 2>/dev/null || true)

  # Reprint steps (move cursor up to overwrite)
  STEP_COUNT=$(echo "$STEPS" | wc -l)
  if [[ -n "$LAST_STEP" ]]; then
    printf "\033[%dA" "$STEP_COUNT"
  fi
  echo "$STEPS"
  LAST_STEP="$STEPS"

  # Check overall run status
  RESULT=$(gh run view "$RUN_ID" --repo "$REPO" --json status,conclusion \
    | python3 -c "import json,sys; r=json.load(sys.stdin); print(r['status'],r.get('conclusion',''))")
  STATUS=$(echo "$RESULT" | awk '{print $1}')
  CONCLUSION=$(echo "$RESULT" | awk '{print $2}')

  if [[ "$STATUS" == "completed" ]]; then
    echo ""
    if [[ "$CONCLUSION" == "success" ]]; then
      echo "✓ CI passed (${ELAPSED}s)"
      break
    else
      echo "✗ CI failed: $CONCLUSION"
      echo ""
      echo "── Failed step output ──────────────────────────────────"
      gh run view "$RUN_ID" --repo "$REPO" --log-failed 2>/dev/null | tail -50 || true
      exit 1
    fi
  fi

  sleep $POLL
  ELAPSED=$((ELAPSED + POLL))

  if [[ $ELAPSED -ge $TIMEOUT ]]; then
    echo "✗ Timed out after ${TIMEOUT}s"
    exit 1
  fi
done

# ── 4. Smoke-test the live site ───────────────────────────────────────────────
echo "▶ Smoke-testing $SITE…"
sleep 5  # brief CDN propagation window

HTTP=$(curl -sI "$SITE" | head -1 | awk '{print $2}')
if [[ "$HTTP" == "200" ]]; then
  echo "✓ Site live: $SITE (HTTP $HTTP)"
else
  echo "✗ Unexpected HTTP $HTTP — CDN may still be propagating"
  exit 1
fi

# Check favicon
FAV_HTTP=$(curl -sI "${SITE}favicon.svg" | head -1 | awk '{print $2}')
if [[ "$FAV_HTTP" == "200" ]]; then
  echo "✓ Favicon live: ${SITE}favicon.svg"
else
  echo "⚠ Favicon HTTP $FAV_HTTP"
fi

# Check eval page
EVAL_HTTP=$(curl -sI "${SITE}eval/" | head -1 | awk '{print $2}')
if [[ "$EVAL_HTTP" == "200" ]]; then
  echo "✓ Eval page live: ${SITE}eval/"
else
  echo "⚠ Eval page HTTP $EVAL_HTTP"
fi

echo ""
echo "🚀  $SITE"
