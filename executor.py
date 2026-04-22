"""
executor.py — Action execution engine.
Supports: bash, python_exec, pyautogui, write_file.
Every action requires human approval unless auto_approve=True is set
at the call site (never done by default for destructive ops).
"""

import os
import sys
import json
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass
from typing import Any, Optional


ALLOWED_ACTION_TYPES = {"bash", "python_exec", "pyautogui", "playwright", "write_file", "read_file", "noop"}

# Autonomy levels:
#   off         — approve everything (original behaviour)
#   normal      — auto-approve safe actions; confirm only destructive ones  (default)
#   full        — approve everything automatically, no prompts at all
import os as _os
AUTONOMY = _os.environ.get("AGENT_AUTONOMY", "normal").lower()

# Bash/python patterns that are considered destructive (require confirmation)
_DESTRUCTIVE_PATTERNS = [
    r"rm\s+-[rf]",          # rm -rf
    r"rm\s+",               # any rm
    r"\bmkfs\b",            # format disk
    r"\bdd\b.*of=",          # disk write
    r"\bshred\b",
    r"\bchmod\b.*777",
    r"> /",                  # redirect to system path
    r"sudo\s+",              # sudo anything
    r"\bkill\b",
    r"\bpkill\b",
    r"\breboot\b",
    r"\bshutdown\b",
    r"\bcurl\b.*\|.*sh",    # curl | sh
    r"\bwget\b.*\|.*sh",
    r"DROP\s+TABLE",         # SQL destructive
    r"DELETE\s+FROM",
    r"truncate",
]

import re as _re
_DESTRUCTIVE_RE = _re.compile("|".join(_DESTRUCTIVE_PATTERNS), _re.IGNORECASE)


def _is_destructive(action: "Action") -> bool:
    """Return True if the action could irreversibly damage the system."""
    t = action.action_type
    p = action.payload

    if t == "write_file":
        # Overwriting sensitive system paths is destructive
        path = str(p.get("path", ""))
        danger_prefixes = ("/etc/", "/usr/", "/bin/", "/sbin/", "/System/", "/boot/")
        return any(path.startswith(pfx) for pfx in danger_prefixes)

    if t in ("bash", "python_exec"):
        code = p.get("command", "") or p.get("code", "")
        return bool(_DESTRUCTIVE_RE.search(code))

    return False  # playwright, pyautogui, read_file, noop — never destructive


@dataclass
class Action:
    action_type: str          # one of ALLOWED_ACTION_TYPES
    description: str          # human-readable summary
    payload: dict[str, Any]   # action-specific params
    model_source: str         # which model proposed this
    confidence: float = 0.0   # 0.0–1.0


@dataclass
class ActionResult:
    success: bool
    output: str
    error: Optional[str] = None
    user_feedback: Optional[str] = None  # freeform instruction from approval gate


def parse_action_from_text(text: str, model_name: str) -> Optional[Action]:
    """
    Extract a structured action from model output.
    Models are prompted to emit a JSON block like:
        ```json
        {"action_type": "bash", "description": "...", "payload": {...}, "confidence": 0.9}
        ```
    """
    import re
    # Try fenced JSON block first
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if not match:
        # Try bare JSON object anywhere in the text
        match = re.search(r"(\{[^{}]*\"action_type\"[^{}]*\})", text, re.DOTALL)
    if not match:
        return None
    try:
        obj = json.loads(match.group(1))
        atype = obj.get("action_type", "noop")
        if atype not in ALLOWED_ACTION_TYPES:
            return None
        return Action(
            action_type=atype,
            description=obj.get("description", "(no description)"),
            payload=obj.get("payload", {}),
            model_source=model_name,
            confidence=float(obj.get("confidence", 0.5)),
        )
    except (json.JSONDecodeError, ValueError):
        return None


def _prompt_approval(action: Action) -> "bool | str":
    """
    Interactive terminal approval gate.
    Returns:
      True        — approved, execute
      False       — rejected, skip
      str         — freeform feedback to feed back to models before retrying
    """
    border = "─" * 60
    print(f"\n{'═'*60}")
    print(f"  ACTION PROPOSAL from [{action.model_source}]")
    print(f"  Type       : {action.action_type}")
    print(f"  Confidence : {action.confidence:.0%}")
    print(f"  Description: {action.description}")
    print(f"{border}")
    payload_str = json.dumps(action.payload, indent=2)
    for line in payload_str.splitlines():
        print(f"  {line}")
    print(f"{'═'*60}")
    print("  y = approve  |  n = reject  |  q = quit  |  anything else = feedback to models")
    while True:
        ans = input("  → ").strip()
        low = ans.lower()
        if low in ("y", "yes"):
            return True
        if low in ("n", "no"):
            return False
        if low in ("q", "quit"):
            print("Exiting.")
            sys.exit(0)
        if ans:
            return ans  # freeform feedback
        print("  Please enter y, n, q, or any instruction for the models.")


def execute(action: Action, auto_approve: bool = False) -> ActionResult:
    # ── Compliance lattice ────────────────────────────────────────────────
    # Always run for destructive actions. Non-destructive actions get a
    # lightweight audit log entry but are never blocked by compliance alone.
    if action.action_type not in ("read_file", "noop"):
        from compliance import evaluate, infer_context, print_decision
        path = (action.payload.get("path") or
                action.payload.get("command") or
                action.payload.get("code") or
                action.payload.get("script") or
                action.description or "")
        ctx = infer_context(path, action.description)
        decision = evaluate(action.action_type, action.payload, ctx)

        if not decision.permitted:
            print_decision(decision)
            return ActionResult(
                success=False, output="",
                error=f"Compliance BLOCK — {decision.justification}",
            )

        if decision.mitigations_required and _is_destructive(action):
            print_decision(decision)

    # ── Autonomy gate ─────────────────────────────────────────────────────
    needs_confirm = False

    if not auto_approve:
        if AUTONOMY == "off":
            needs_confirm = action.action_type not in ("read_file", "noop")
        elif AUTONOMY == "normal":
            needs_confirm = _is_destructive(action)
        elif AUTONOMY == "full":
            needs_confirm = False

    if needs_confirm:
        approved = _prompt_approval(action)
        if approved is False:
            return ActionResult(success=False, output="", error="User rejected action.")
        if isinstance(approved, str):
            return ActionResult(success=False, output="", error="User provided feedback.",
                                user_feedback=approved)
    elif action.action_type not in ("read_file", "noop") and AUTONOMY != "off":
        print(f"\n  \u25b6 Auto-running [{action.action_type}]: {action.description}")

    try:
        if action.action_type == "noop":
            return ActionResult(success=True, output="noop")

        elif action.action_type == "bash":
            return _run_bash(action.payload)

        elif action.action_type == "python_exec":
            return _run_python(action.payload)

        elif action.action_type == "pyautogui":
            return _run_pyautogui(action.payload)

        elif action.action_type == "write_file":
            return _write_file(action.payload)

        elif action.action_type == "playwright":
            return _run_playwright(action.payload)

        elif action.action_type == "read_file":
            return _read_file(action.payload)

        else:
            return ActionResult(success=False, output="", error=f"Unknown action type: {action.action_type}")
    except Exception as e:
        return ActionResult(success=False, output="", error=str(e))


def _run_bash(payload: dict) -> ActionResult:
    cmd = payload.get("command", "")
    timeout = int(payload.get("timeout", 30))
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    combined = result.stdout + (f"\nSTDERR:\n{result.stderr}" if result.stderr.strip() else "")
    return ActionResult(
        success=result.returncode == 0,
        output=combined.strip(),
        error=result.stderr.strip() if result.returncode != 0 else None,
    )


def _run_python(payload: dict) -> ActionResult:
    code = payload.get("code", "")
    timeout = int(payload.get("timeout", 30))
    # Write to temp file and run in subprocess to avoid polluting this process
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(textwrap.dedent(code))
        tmp_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        combined = result.stdout + (f"\nSTDERR:\n{result.stderr}" if result.stderr.strip() else "")
        return ActionResult(
            success=result.returncode == 0,
            output=combined.strip(),
            error=result.stderr.strip() if result.returncode != 0 else None,
        )
    finally:
        os.unlink(tmp_path)


def _run_pyautogui(payload: dict) -> ActionResult:
    import pyautogui  # type: ignore
    pyautogui.FAILSAFE = True  # move mouse to top-left corner to abort

    op = payload.get("op")
    if op == "screenshot":
        path = payload.get("path", "/tmp/screenshot.png")
        pyautogui.screenshot(path)
        return ActionResult(success=True, output=f"Screenshot saved to {path}")

    elif op == "click":
        x, y = payload["x"], payload["y"]
        button = payload.get("button", "left")
        pyautogui.click(x, y, button=button)
        return ActionResult(success=True, output=f"Clicked ({x},{y}) [{button}]")

    elif op == "type":
        text = payload.get("text", "")
        interval = float(payload.get("interval", 0.02))
        pyautogui.typewrite(text, interval=interval)
        return ActionResult(success=True, output=f"Typed: {text!r}")

    elif op == "hotkey":
        keys = payload.get("keys", [])
        pyautogui.hotkey(*keys)
        return ActionResult(success=True, output=f"Hotkey: {keys}")

    elif op == "moveTo":
        x, y = payload["x"], payload["y"]
        duration = float(payload.get("duration", 0.25))
        pyautogui.moveTo(x, y, duration=duration)
        return ActionResult(success=True, output=f"Moved to ({x},{y})")

    elif op == "scroll":
        x, y = payload.get("x", None), payload.get("y", None)
        clicks = int(payload.get("clicks", 3))
        if x is not None and y is not None:
            pyautogui.scroll(clicks, x=x, y=y)
        else:
            pyautogui.scroll(clicks)
        return ActionResult(success=True, output=f"Scrolled {clicks} clicks")

    else:
        return ActionResult(success=False, output="", error=f"Unknown pyautogui op: {op}")


def _run_playwright(payload: dict) -> ActionResult:
    """
    Runs a Playwright script. The payload must contain a 'script' key with
    async Python code that has access to a `page` object (Playwright Page).
    Optional: 'browser' (chromium|firefox|webkit), 'headless' (bool), 'timeout' (int seconds).

    Example payload:
        {
          "browser": "chromium",
          "headless": false,
          "timeout": 30,
          "script": "await page.goto('https://example.com')\nprint(await page.title())"
        }
    """
    script_body = payload.get("script", "")
    browser_type = payload.get("browser", "chromium")
    headless = payload.get("headless", False)  # default visible so user can watch
    timeout = int(payload.get("timeout", 30))

    # Wrap the user script in a full async Playwright harness
    full_code = f"""import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as pw:
        browser = await pw.{browser_type}.launch(headless={headless})
        page = await browser.new_page()
        try:
{textwrap.indent(textwrap.dedent(script_body), '            ')}
        finally:
            await browser.close()

asyncio.run(run())
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(full_code)
        tmp_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        combined = result.stdout + (f"\nSTDERR:\n{result.stderr}" if result.stderr.strip() else "")
        return ActionResult(
            success=result.returncode == 0,
            output=combined.strip(),
            error=result.stderr.strip() if result.returncode != 0 else None,
        )
    finally:
        os.unlink(tmp_path)


def _write_file(payload: dict) -> ActionResult:
    path = payload.get("path")
    content = payload.get("content", "")
    mode = payload.get("mode", "w")
    if not path:
        return ActionResult(success=False, output="", error="No path specified")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, mode) as f:
        f.write(content)
    return ActionResult(success=True, output=f"Wrote {len(content)} chars to {path}")


def _read_file(payload: dict) -> ActionResult:
    path = payload.get("path")
    if not path:
        return ActionResult(success=False, output="", error="No path specified")
    try:
        with open(path) as f:
            content = f.read()
        return ActionResult(success=True, output=content)
    except FileNotFoundError:
        return ActionResult(success=False, output="", error=f"File not found: {path}")
