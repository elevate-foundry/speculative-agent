#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env if present (never committed — put API keys here)
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

# Create venv if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "[run.sh] Creating virtual environment..."
    python3 -m venv .venv
fi

# Install/sync dependencies
echo "[run.sh] Checking dependencies..."
.venv/bin/pip install -q -r requirements.txt

# Install Playwright browsers if not already installed
if ! .venv/bin/python -c "from playwright.sync_api import sync_playwright; sync_playwright().__enter__().chromium" 2>/dev/null; then
    echo "[run.sh] Installing Playwright browsers..."
    .venv/bin/playwright install chromium
fi

# Check Ollama is running
if ! curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "[run.sh] Ollama is not running. Starting it..."
    ollama serve &
    sleep 2
fi

# OpenRouter — optional free cloud models
if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "[run.sh] Tip: set OPENROUTER_API_KEY to add free cloud models to the race."
    echo "         Get a free key at https://openrouter.ai/keys"
    echo "         e.g. export OPENROUTER_API_KEY=sk-or-..."
fi

echo "[run.sh] Starting agent..."
# Default to full autonomy + performance intelligence when called with no flags
if [ $# -eq 0 ]; then
    exec .venv/bin/python agent.py --autonomy full
else
    exec .venv/bin/python agent.py "$@"
fi
