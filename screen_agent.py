#!/usr/bin/env python3
"""
screen_agent.py — Vision-enabled machine controller with screen recording
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Uses a vision model (llava, gemma3, or OpenRouter vision model) to see your
screen, propose actions, and control your machine via pyautogui — all gated
through the compliance lattice.

Screen is recorded with ffmpeg for full auditability.

Usage:
    python screen_agent.py "open Safari and go to example.com"
    python screen_agent.py --model llava "click the search bar"
    python screen_agent.py --no-record "take a screenshot"

Environment:
    OLLAMA_HOST          Ollama base URL (default: http://localhost:11434)
    OPENROUTER_API_KEY   For cloud vision models
    AGENT_AUTONOMY       normal|full (default: normal = ask before actions)
"""

import asyncio
import sys
import os
import signal
import subprocess
import time
import base64
import tempfile
import json
import argparse
from datetime import datetime
from typing import Optional

# Load .env
_env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

sys.path.insert(0, os.path.dirname(__file__))

from config import OLLAMA_BASE, ModelInfo
from supervisor import supervise_race, score_reasoning
from executor import execute, Action, ActionResult, parse_action_from_text
from compliance_sdk import evaluate_action

# ─── ffmpeg screen recorder ────────────────────────────────────────────────

class ScreenRecorder:
    """Records the screen using ffmpeg + macOS AVFoundation."""

    def __init__(self, output_dir: str = "recordings"):
        self.output_dir = output_dir
        self.process: Optional[subprocess.Popen] = None
        self.output_path: Optional[str] = None

    def start(self) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_path = os.path.join(self.output_dir, f"session_{ts}.mp4")

        # Discover screen device index — macOS AVFoundation
        # "Capture screen 0" is typically index 1 on macOS (0 is camera)
        screen_idx = self._find_screen_device()

        cmd = [
            "ffmpeg",
            "-y",                        # overwrite
            "-f", "avfoundation",
            "-framerate", "10",          # 10 fps is enough for agent replay
            "-capture_cursor", "1",
            "-capture_mouse_clicks", "1",
            "-i", f"{screen_idx}:none",  # screen:audio (none = no audio)
            "-c:v", "h264_videotoolbox", # hardware encoder on Apple Silicon
            "-b:v", "2M",
            "-pix_fmt", "yuv420p",
            self.output_path,
        ]

        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"  [recorder] ● Recording to {self.output_path} (pid {self.process.pid})")
        return self.output_path

    def stop(self) -> Optional[str]:
        if self.process and self.process.poll() is None:
            # Send 'q' to ffmpeg for graceful stop
            try:
                self.process.stdin.write(b"q")
                self.process.stdin.flush()
            except Exception:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            print(f"  [recorder] ■ Stopped. Saved: {self.output_path}")
        return self.output_path

    @staticmethod
    def _find_screen_device() -> str:
        """Find the AVFoundation screen capture device index."""
        try:
            result = subprocess.run(
                ["ffmpeg", "-f", "avfoundation", "-list_devices", "true", "-i", ""],
                capture_output=True, text=True, timeout=5,
            )
            # Parse stderr for "Capture screen" device
            for line in result.stderr.splitlines():
                if "Capture screen" in line:
                    # Line format: [AVFoundation ...] [N] Capture screen 0
                    for part in line.split("["):
                        part = part.strip()
                        if part and part[0].isdigit() and "]" in part:
                            idx = part.split("]")[0]
                            return idx
        except Exception:
            pass
        return "1"  # default: screen is usually device 1


# ─── Vision screenshot helper ──────────────────────────────────────────────

def take_screenshot() -> tuple[str, str]:
    """Take a screenshot, return (base64_string, file_path)."""
    from PIL import ImageGrab
    path = os.path.join(os.path.dirname(__file__), ".screen_agent_frame.png")
    img = ImageGrab.grab()
    img.save(path)
    with open(path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    return b64, path


def screen_dimensions() -> tuple[int, int]:
    """Return logical screen width, height."""
    import pyautogui
    size = pyautogui.size()
    return size.width, size.height


# ─── Vision system prompt ───────────────────────────────────────────────────

VISION_SYSTEM_PROMPT = """You are a vision-enabled machine control agent running on macOS.
You can SEE the user's screen via a screenshot attached to each message.

Your job:
1. Observe the current screen state from the screenshot.
2. Reason step-by-step about what you see and what needs to happen.
3. Output ONE structured action to accomplish the next step.

ALWAYS end your response with a JSON action block inside triple backticks:

```json
{
  "action_type": "<pyautogui|bash|playwright|write_file|read_file|noop>",
  "description": "<what this does and WHY based on what you see>",
  "confidence": <float 0.0-1.0>,
  "payload": { ... }
}
```

pyautogui payload schemas (for controlling the desktop):
  screenshot:  { "op": "screenshot" }
  click:       { "op": "click", "x": <int>, "y": <int>, "button": "left" }
  type:        { "op": "type", "text": "..." }
  hotkey:      { "op": "hotkey", "keys": ["command", "space"] }
  moveTo:      { "op": "moveTo", "x": <int>, "y": <int> }
  scroll:      { "op": "scroll", "clicks": <int>, "x": <int>, "y": <int> }

bash payload:   { "command": "open -a Safari" }
playwright:     { "browser": "chromium", "headless": false, "script": "..." }

CRITICAL RULES:
- ALWAYS reference specific pixel coordinates from the screenshot.
- Describe what you see FIRST, then decide the action.
- Use `open -a AppName` to launch applications.
- Use pyautogui for desktop interaction (clicking, typing in native apps).
- Use playwright for web automation (better than clicking in browser).
- Output noop when the task is complete.
"""


# ─── Main loop ──────────────────────────────────────────────────────────────

async def run_screen_agent(
    task: str,
    model_name: str = "llava:latest",
    max_steps: int = 15,
    record: bool = True,
    auto_approve: bool = False,
):
    """
    Vision agent loop:
    1. Screenshot → send to vision model
    2. Model proposes action
    3. Compliance gate
    4. Execute (with approval)
    5. Repeat
    """
    w, h = screen_dimensions()
    print(f"\n{'━'*60}")
    print(f"  SCREEN AGENT")
    print(f"  Model  : {model_name}")
    print(f"  Screen : {w}x{h}")
    print(f"  Task   : {task}")
    print(f"  Record : {'ON' if record else 'OFF'}")
    print(f"  Approve: {'auto' if auto_approve else 'ask'}")
    print(f"{'━'*60}\n")

    recorder = ScreenRecorder()
    recording_path = None
    if record:
        recording_path = recorder.start()
        time.sleep(0.5)  # let ffmpeg initialize

    model = ModelInfo(name=model_name, size_gb=0.0, provider="ollama")

    history = []

    try:
        for step in range(1, max_steps + 1):
            print(f"\n{'─'*60}")
            print(f"  STEP {step}/{max_steps}")
            print(f"{'─'*60}")

            # 1. Screenshot
            print("  [vision] Taking screenshot...")
            b64, ss_path = take_screenshot()

            # 2. Build prompt with history
            prompt_parts = [f"Screen: {w}x{h}px"]
            if history:
                prompt_parts.append("\n=== Previous steps ===")
                for i, h_entry in enumerate(history[-3:], 1):
                    prompt_parts.append(f"Step {i}: {h_entry['action']} → {h_entry['result'][:200]}")
            prompt_parts.append(f"\n=== Task ===\n{task}")
            prompt = "\n".join(prompt_parts)

            # 3. Race (single vision model, but could be multiple)
            action, streams = await supervise_race(
                model_names=[model],
                prompt=prompt,
                system_prompt=VISION_SYSTEM_PROMPT,
                ollama_base=OLLAMA_BASE,
                verbose=True,
                live_output=True,
                screenshot_b64=b64,
                max_tokens=1024,
            )

            if action is None:
                print("\n  [agent] No valid action produced. Raw output:")
                for s in streams:
                    if s.text:
                        print(f"  --- {s.model_name} ---")
                        print(f"  {s.text[:600]}")
                continue

            # 4. Compliance gate
            cmd = action.payload.get("command", action.payload.get("path",
                  action.payload.get("script", action.description)))
            compliance = evaluate_action(action.action_type, str(cmd))

            print(f"\n  [compliance] {compliance.braille_word}  "
                  f"{'✓' if compliance.permitted else '✗'}  "
                  f"ℒ={compliance.lagrangian:.2f}  "
                  f"{compliance.verdict}")

            if not compliance.permitted:
                print(f"  [compliance] BLOCKED: {compliance.blocking}")
                print(f"  [compliance] {compliance.justification}")
                history.append({
                    "action": f"BLOCKED {action.action_type}: {action.description}",
                    "result": f"Compliance block: {compliance.blocking}",
                })
                continue

            # 5. Show proposal and get approval
            print(f"\n  [action] {action.action_type}: {action.description}")
            print(f"  [model]  {action.model_source}  confidence={action.confidence:.0%}")
            payload_str = json.dumps(action.payload, indent=2)
            for line in payload_str.splitlines():
                print(f"    {line}")

            if not auto_approve:
                ans = input("\n  Execute? [y/n/q] → ").strip().lower()
                if ans in ("n", "no"):
                    history.append({
                        "action": f"REJECTED {action.action_type}: {action.description}",
                        "result": "User rejected",
                    })
                    continue
                if ans in ("q", "quit"):
                    break
                if ans not in ("y", "yes", ""):
                    # Freeform feedback
                    history.append({
                        "action": "user_feedback",
                        "result": ans,
                    })
                    task = f"{task}\n\nHuman feedback: {ans}"
                    continue

            # 6. Execute
            result = execute(action, auto_approve=True)

            status = "✓" if result.success else "✗"
            output = result.output or result.error or ""
            print(f"\n  [{status}] {output[:300]}")

            history.append({
                "action": f"{action.action_type}: {action.description}",
                "result": output[:300],
            })

            # noop = done
            if action.action_type == "noop":
                print(f"\n  [agent] Task complete.")
                break

            # Pause between steps to let UI settle
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n\n  [agent] Interrupted by user.")
    finally:
        if record:
            recorder.stop()
            if recording_path:
                size = os.path.getsize(recording_path) if os.path.exists(recording_path) else 0
                print(f"\n  Recording: {recording_path} ({size / 1024:.0f} KB)")

    print(f"\n{'━'*60}")
    print(f"  Session complete. {len(history)} steps executed.")
    print(f"{'━'*60}")


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Vision-enabled screen control agent with compliance lattice",
    )
    parser.add_argument("task", nargs="?", help="Task to perform")
    parser.add_argument("--model", "-m", default="llava:latest",
                        help="Vision model (default: llava:latest)")
    parser.add_argument("--steps", "-s", type=int, default=15,
                        help="Max steps (default: 15)")
    parser.add_argument("--no-record", action="store_true",
                        help="Disable screen recording")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-approve all actions (dangerous!)")
    args = parser.parse_args()

    task = args.task
    if not task:
        print("Screen Agent — Vision + Compliance Lattice + ffmpeg Recording")
        print("─" * 60)
        task = input("Task: ").strip()
        if not task:
            print("No task provided.")
            sys.exit(1)

    asyncio.run(run_screen_agent(
        task=task,
        model_name=args.model,
        max_steps=args.steps,
        record=not args.no_record,
        auto_approve=args.auto,
    ))


if __name__ == "__main__":
    main()
