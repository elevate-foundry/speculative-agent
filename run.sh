#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

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

echo "[run.sh] Starting agent..."
exec .venv/bin/python agent.py "$@"
