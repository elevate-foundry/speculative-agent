#!/usr/bin/env python3
"""
agent.py — Parallel Speculative CoT Machine Controller
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
All locally available Ollama models race in parallel with chain-of-thought
reasoning. A supervisor monitors streams in real-time and can short-circuit
the race when any model produces high-confidence output. Every proposed
action requires your explicit approval before execution.

Usage:
    python agent.py                  # interactive REPL
    python agent.py "your task"      # single task then exit
    python agent.py --list-models    # show available models & exit
"""

import asyncio
import sys
import os
import argparse
import json
from typing import Optional

from config import discover_and_warmup, HardwareProfile, ModelInfo, OLLAMA_BASE
from supervisor import supervise_race, print_race_summary
from executor import execute, Action, ActionResult


SYSTEM_PROMPT = """You are a machine control agent running on macOS.
The user will give you a task. Your job is to reason step-by-step and then
output ONE structured action to accomplish it (or the next step of it).

ALWAYS end your response with a JSON action block inside triple backticks:

```json
{
  "action_type": "<bash|python_exec|pyautogui|playwright|write_file|read_file|noop>",
  "description": "<short human-readable summary of what this does>",
  "confidence": <float 0.0-1.0>,
  "payload": {
    <action-specific fields>
  }
}
```

Action payload schemas:
  bash:         { "command": "...", "timeout": 30 }
  python_exec:  { "code": "...", "timeout": 30 }
  pyautogui:    { "op": "screenshot|click|type|hotkey|moveTo|scroll", ... }
  playwright:   { "browser": "chromium", "headless": false, "timeout": 30,
                  "script": "<async Python using `page` object>" }
  write_file:   { "path": "...", "content": "...", "mode": "w" }
  read_file:    { "path": "..." }
  noop:         {}

WHEN TO USE playwright vs pyautogui:
- Use `playwright` for ANY web task: navigating URLs, filling forms, clicking web elements,
  scraping content, logging into websites, sending emails via web UI, web automation.
  The `script` field is async Python with a `page` variable (Playwright AsyncAPI).
  Example: await page.goto('https://mail.google.com')
           await page.get_by_role('button', name='Compose').click()
- Use `pyautogui` only for native desktop GUI control (non-browser apps).
- NEVER refuse a web task as impossible — use playwright.

Only output ONE action block. Reason first, then decide.
If the task is complete, output noop with confidence 1.0.
"""


class Agent:
    def __init__(self, models: list[ModelInfo], hw: HardwareProfile, verbose: bool = True):
        self.models = models
        self.hw = hw
        self.verbose = verbose
        self.history: list[dict] = []  # task + action + result log
        self.last_streams = []          # raw ModelStream objects from last race

    def _build_prompt(self, task: str, context: Optional[str] = None) -> str:
        parts = []
        if self.history:
            parts.append("=== Previous steps ===")
            for i, h in enumerate(self.history[-3:], 1):  # last 3 steps for context
                parts.append(f"Step {i}: {h['task']}")
                if h.get("result"):
                    parts.append(f"  Result: {h['result'][:300]}")
                if not h.get("success") and h.get("error"):
                    parts.append(f"  ERROR: {h['error']}")
                    parts.append(f"  -> You must fix this error and try a different approach.")
        if context:
            parts.append(f"\n=== Context ===\n{context}")
        parts.append(f"\n=== Current task ===\n{task}")
        return "\n".join(parts)

    async def run_task(self, task: str, max_steps: int = 20, max_retries_per_step: int = 2) -> Optional[ActionResult]:
        """
        Infinite pipeline mode: races models, executes the winner's action, feeds
        the result back, and races again — until a model returns noop (done) or
        max_steps is reached. Each step can retry up to max_retries_per_step times
        on failure before moving on.
        """
        model_names = [m.name for m in self.models]
        last_result: Optional[ActionResult] = None
        consecutive_failures = 0

        for step in range(1, max_steps + 1):
            print(f"\n{'━'*60}")
            print(f"  STEP {step}/{max_steps}  —  {task[:70]}")
            print(f"{'━'*60}")

            prompt = self._build_prompt(task)

            action, streams = await supervise_race(
                model_names=model_names,
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT,
                ollama_base=OLLAMA_BASE,
                verbose=self.verbose,
                live_output=True,
            )
            self.last_streams = streams

            if self.verbose:
                print_race_summary(streams)

            if action is None:
                print("\n[agent] No model produced a valid action. Showing raw outputs:\n")
                for s in streams:
                    if s.text:
                        print(f"--- {s.model_name} ---")
                        print(s.text[:800])
                        print()
                consecutive_failures += 1
                if consecutive_failures >= max_retries_per_step:
                    print(f"[agent] {consecutive_failures} consecutive steps with no valid action. Stopping.")
                    break
                continue

            consecutive_failures = 0

            # noop means the model considers the task complete
            if action.action_type == "noop":
                print(f"\n[agent] ✓ Task complete (declared by {action.model_source} at step {step})")
                if action.description and action.description != "(no description)":
                    print(f"  {action.description}")
                break

            print(f"\n[agent] Step {step} — {action.action_type} from [{action.model_source}]: {action.description}")

            result = execute(action)
            last_result = result

            entry = {
                "task": task,
                "step": step,
                "action_type": action.action_type,
                "model": action.model_source,
                "description": action.description,
                "success": result.success,
                "result": result.output[:500] if result.output else "",
                "error": result.error,
            }
            self.history.append(entry)

            if result.success:
                print(f"\n[agent] ✓ Step {step} succeeded")
                if result.output:
                    print(result.output[:1000])
            else:
                print(f"\n[agent] ✗ Step {step} failed: {result.error}")
                consecutive_failures += 1
                if consecutive_failures >= max_retries_per_step:
                    print(f"[agent] {consecutive_failures} consecutive failures. Stopping pipeline.")
                    break
                print(f"[agent] Feeding error back to models for next step...\n")
                # history already has the error — next iteration will include it in prompt
                continue

            consecutive_failures = 0

        else:
            print(f"\n[agent] Reached max steps ({max_steps}). Pipeline stopped.")

        return last_result

    def show_history(self):
        if not self.history:
            print("No history yet.")
            return
        print("\n" + "═" * 60)
        print("  SESSION HISTORY")
        print("─" * 60)
        for i, h in enumerate(self.history, 1):
            status = "✓" if h["success"] else "✗"
            step = f"s{h['step']} " if "step" in h else ""
            print(f"  {i}. [{status}] {step}[{h['model']}] {h['action_type']}: {h['task'][:55]}")
        print("═" * 60)

    def show_thoughts(self):
        """Print full raw reasoning from the last race for all models."""
        if not self.last_streams:
            print("No race has run yet.")
            return
        from supervisor import _model_label, _DIM, _RESET
        print("\n" + "═" * 60)
        print("  FULL REASONING — last race")
        for s in self.last_streams:
            print("\n" + "─" * 60)
            print(f"  {_model_label(s.model_name)}  "
                  f"{_DIM}tokens={s.token_count} {s.elapsed_ms:.0f}ms{_RESET}")
            print("─" * 60)
            print(s.text if s.text else "(no output)")
        print("\n" + "═" * 60)

    def show_models(self):
        print("\n" + "═" * 60)
        print("  ACTIVE MODELS")
        print("─" * 60)
        for m in self.models:
            print(f"  {m.name:<35} {m.size_gb:.1f} GB  "
                  f"warmup={m.warm_latency_ms:.0f}ms")
        print(f"\n  Hardware limit: {self.hw.max_parallel_models} concurrent")
        print("═" * 60)


async def interactive_repl(agent: Agent):
    print("\n" + "═" * 60)
    print("  Machine Control Agent — Interactive Mode")
    print("  Commands: /models /history /thoughts /quit")
    print("═" * 60 + "\n")

    while True:
        try:
            task = input("Task → ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not task:
            continue
        if task == "/quit":
            break
        elif task == "/models":
            agent.show_models()
        elif task == "/history":
            agent.show_history()
        elif task == "/thoughts":
            agent.show_thoughts()
        else:
            await agent.run_task(task)


async def main():
    parser = argparse.ArgumentParser(description="Parallel Speculative CoT Machine Controller")
    parser.add_argument("task", nargs="?", help="Single task to run, then exit")
    parser.add_argument("--list-models", action="store_true", help="List available models and exit")
    parser.add_argument("--quiet", action="store_true", help="Suppress supervisor stream logs")
    parser.add_argument("--max-steps", type=int, default=20, help="Max pipeline steps per task (default 20)")
    args = parser.parse_args()

    print("Discovering and warming up Ollama models...")
    models, hw = await discover_and_warmup(verbose=True)

    agent = Agent(models=models, hw=hw, verbose=not args.quiet)

    if args.list_models:
        agent.show_models()
        return

    if args.task:
        await agent.run_task(args.task, max_steps=args.max_steps)
    else:
        await interactive_repl(agent)


if __name__ == "__main__":
    asyncio.run(main())
