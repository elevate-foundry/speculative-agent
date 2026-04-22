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
import base64
import argparse
import json
import tempfile
from typing import Optional

from config import (
    discover_and_warmup, HardwareProfile, ModelInfo, OLLAMA_BASE,
    classify_task_tier, list_openrouter_models, BUDGET_TIER, OPENROUTER_API_KEY,
    is_private_task,
)
from providers import register_key, active_providers, PROVIDER_REGISTRY
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
        self.models = models           # base pool (local + free cloud)
        self.hw = hw
        self.verbose = verbose
        self.history: list[dict] = []  # task + action + result log
        self.last_streams = []          # raw ModelStream objects from last race
        self._or_cache: dict[str, list[ModelInfo]] = {}  # tier -> upgraded OR models
        self.session_cost_usd: float = 0.0

    def _get_screen_context(self) -> tuple[str, Optional[str]]:
        """
        Takes a screenshot and returns (text_context, screenshot_path).
        text_context describes screen size and the path to the screenshot.
        Returns ('', None) if pyautogui/Pillow is unavailable.
        """
        try:
            import pyautogui
            size = pyautogui.size()
            path = os.path.join(tempfile.gettempdir(), "agent_screen.png")
            pyautogui.screenshot(path)
            ctx = (f"Screen: {size.width}x{size.height}px. "
                   f"Current screenshot saved to {path}. "
                   f"Use these exact pixel dimensions for any click/moveTo coordinates.")
            return ctx, path
        except Exception:
            return "", None

    def _build_prompt(self, task: str, context: Optional[str] = None,
                      screen_ctx: Optional[str] = None) -> str:
        parts = []
        if self.history:
            parts.append("=== Previous steps ===")
            for i, h in enumerate(self.history[-3:], 1):  # last 3 steps for context
                parts.append(f"Step {i}: {h['task']}")
                if h.get("action_type") == "user_feedback":
                    parts.append(f"  *** HUMAN INSTRUCTION: {h['description']} ***")
                    parts.append(f"  -> You MUST follow this instruction exactly in your next action.")
                elif h.get("result"):
                    parts.append(f"  Result: {h['result'][:300]}")
                if not h.get("success") and h.get("error") and h.get("action_type") != "user_feedback":
                    parts.append(f"  ERROR: {h['error']}")
                    parts.append(f"  -> You must fix this error and try a different approach.")
        if screen_ctx:
            parts.append(f"\n=== Screen context ===\n{screen_ctx}")
        if context:
            parts.append(f"\n=== Context ===\n{context}")
        parts.append(f"\n=== Current task ===\n{task}")
        return "\n".join(parts)

    async def _models_for_tier(self, tier: str) -> list[ModelInfo]:
        """Return the model pool for a given budget tier, upgrading OR models if needed."""
        if tier == "free" or not OPENROUTER_API_KEY:
            return self.models
        if tier not in self._or_cache:
            upgraded_or = await list_openrouter_models(tier=tier)
            # Merge: keep local models, replace OR pool with upgraded set
            local = [m for m in self.models if m.provider == "ollama"]
            self._or_cache[tier] = local + upgraded_or
        return self._or_cache[tier]

    async def run_task(self, task: str, max_steps: int = 20, max_retries_per_step: int = 2) -> Optional[ActionResult]:
        """
        Infinite pipeline mode: races models, executes the winner's action, feeds
        the result back, and races again — until a model returns noop (done) or
        max_steps is reached. Each step can retry up to max_retries_per_step times
        on failure before moving on.
        """
        # Privacy check: sensitive tasks never leave the machine
        if is_private_task(task):
            local_only = [m for m in self.models if m.provider == "ollama"]
            if local_only:
                if self.verbose:
                    print(f"[agent] 🔒 Privacy mode: routing to local models only (sensitive keywords detected)")
                active_models = local_only
                tier = "free"
            else:
                print("[agent] ⚠️  WARNING: task looks sensitive but no local models are loaded. "
                      "Proceeding with cloud (use AGENT_LOCAL=1 to always include local models).")
                active_models = self.models
                tier = classify_task_tier(task)
        else:
            # Auto-detect best budget tier for this task
            tier = classify_task_tier(task)
            if tier != "free" and self.verbose:
                print(f"[agent] Task classifier: tier={tier!r} — upgrading model pool...")
            active_models = await self._models_for_tier(tier)

        last_result: Optional[ActionResult] = None
        consecutive_failures = 0
        last_action_sig: Optional[str] = None
        repeat_count = 0
        MAX_REPEATS = 3

        for step in range(1, max_steps + 1):
            print(f"\n{'━'*60}")
            print(f"  STEP {step}/{max_steps}  —  {task[:70]}")
            print(f"{'━'*60}")

            screen_ctx, screenshot_path = self._get_screen_context()
            prompt = self._build_prompt(task, screen_ctx=screen_ctx)

            # Build base64 image payload for vision-capable OpenRouter models
            screenshot_b64: Optional[str] = None
            if screenshot_path and os.path.exists(screenshot_path):
                with open(screenshot_path, "rb") as f:
                    screenshot_b64 = base64.b64encode(f.read()).decode()

            action, streams = await supervise_race(
                model_names=active_models,
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT,
                ollama_base=OLLAMA_BASE,
                verbose=self.verbose,
                live_output=True,
                screenshot_b64=screenshot_b64,
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

            # User typed freeform feedback instead of y/n — inject and re-race
            if result.user_feedback:
                print(f"\n[agent] Injecting your feedback into next race: {result.user_feedback!r}")
                self.history.append({
                    "task": task,
                    "step": step,
                    "action_type": "user_feedback",
                    "model": "human",
                    "description": result.user_feedback,
                    "success": True,
                    "result": f"USER INSTRUCTION: {result.user_feedback}",
                    "error": None,
                })
                consecutive_failures = 0
                continue

            # Track cost for paid models
            winning_model = next((m for m in active_models if m.name == action.model_source), None)
            step_cost = 0.0
            if winning_model and winning_model.cost_per_token > 0:
                # Rough estimate: tokens in stream * cost_per_token
                winning_stream = next((s for s in streams if s.model_name == action.model_source), None)
                tokens_used = winning_stream.token_count if winning_stream else 0
                step_cost = tokens_used * winning_model.cost_per_token
                self.session_cost_usd += step_cost
                if self.verbose and step_cost > 0:
                    print(f"[agent] 💳 Step cost: ${step_cost:.5f}  |  Session total: ${self.session_cost_usd:.4f}")

            entry = {
                "task": task,
                "step": step,
                "action_type": action.action_type,
                "model": action.model_source,
                "tier": tier,
                "cost_usd": step_cost,
                "description": action.description,
                "success": result.success,
                "result": result.output[:500] if result.output else "",
                "error": result.error,
            }
            self.history.append(entry)

            # Detect repeating action loops
            action_sig = f"{action.action_type}:{action.description[:60]}"
            if action_sig == last_action_sig:
                repeat_count += 1
                if repeat_count >= MAX_REPEATS:
                    print(f"[agent] ⚠ Same action repeated {MAX_REPEATS}x — injecting hint and breaking loop")
                    self.history.append({
                        "task": task, "step": step, "action_type": "user_feedback",
                        "model": "system", "description": "loop_break",
                        "success": True, "tier": tier, "cost_usd": 0.0,
                        "result": f"SYSTEM: You have repeated '{action.action_type}' {MAX_REPEATS} times. "
                                  f"The task requires a DIFFERENT action now. "
                                  f"If you wrote a file, the next step must be bash/playwright/pyautogui to OPEN it. "
                                  f"If you are stuck, emit noop to stop.",
                        "error": None,
                    })
                    repeat_count = 0
            else:
                repeat_count = 0
            last_action_sig = action_sig

            if result.success:
                print(f"\n[agent] ✓ Step {step} succeeded")
                if result.output:
                    print(result.output[:1000])
                consecutive_failures = 0
            else:
                print(f"\n[agent] ✗ Step {step} failed: {result.error}")
                consecutive_failures += 1
                if consecutive_failures >= max_retries_per_step:
                    print(f"[agent] {consecutive_failures} consecutive failures. Stopping pipeline.")
                    break
                continue

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
        total_cost = sum(h.get("cost_usd", 0) for h in self.history)
        for i, h in enumerate(self.history, 1):
            status = "✓" if h["success"] else "✗"
            step = f"s{h.get('step','?')} " if "step" in h else ""
            cost = f" ${h['cost_usd']:.5f}" if h.get("cost_usd") else ""
            tier = f" [{h.get('tier','free')}]" if h.get("tier", "free") != "free" else ""
            print(f"  {i}. [{status}] {step}[{h['model']}]{tier} {h['action_type']}: {h['task'][:45]}{cost}")
        if total_cost > 0:
            print(f"\n  Session spend: ${total_cost:.4f} USD")
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
            if m.provider == "openrouter":
                ctx = f"{m.context_length//1000}k ctx" if m.context_length else "?k ctx"
                tag = f"☁ openrouter    {ctx}  free"
                warmup = "(catalog)"
            elif m.provider == "ollama":
                tag = f"⬡ local         {m.size_gb:.1f} GB"
                warmup = f"{m.warm_latency_ms:.0f}ms"
            else:
                tag = f"⚡ {m.provider:<12} direct"
                warmup = "(direct)"
            print(f"  {m.name:<50} {tag}  {warmup}")
        unused = [p.name for p in PROVIDER_REGISTRY if not p.api_key]
        if unused:
            print(f"\n  Inactive (no key): {', '.join(unused)}")
            print(f"  Set e.g. OPENAI_API_KEY=sk-... to add direct provider to the race")
        print(f"\n  Hardware limit: {self.hw.max_parallel_models} concurrent")
        print("═" * 60)


async def interactive_repl(agent: Agent):
    import executor as _exe
    autonomy = _exe.AUTONOMY
    budget = os.environ.get("AGENT_BUDGET", "free")
    autonomy_icon = {"off": "🔒 approve-all", "normal": "⚡ smart-approve", "full": "🤖 fully autonomous"}
    budget_icon   = {"free": "free", "standard": "💳 standard", "performance": "💎 performance"}
    print("\n" + "═" * 60)
    print("  Machine Control Agent — Interactive Mode")
    print(f"  Autonomy : {autonomy_icon.get(autonomy, autonomy)}")
    print(f"  Budget   : {budget_icon.get(budget, budget)}")
    print(f"  Models   : {len(agent.models)} active  ({', '.join(m.provider for m in agent.models[:3])}{'...' if len(agent.models) > 3 else ''})")
    print("  Commands : /models /history /thoughts /quit")
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
    parser.add_argument("--budget", choices=["free", "standard", "performance"], default=None,
                        help="Budget ceiling: free (default) | standard | performance. "
                             "Can also set via AGENT_BUDGET env var.")
    parser.add_argument("--local", action="store_true",
                        help="Include local Ollama models in the race alongside cloud models.")
    parser.add_argument("--autonomy", choices=["off", "normal", "full"], default=None,
                        help="off=approve all | normal=approve only destructive (default) | full=fully autonomous")
    args = parser.parse_args()

    if args.budget:
        os.environ["AGENT_BUDGET"] = args.budget
        import config as _cfg
        _cfg.BUDGET_TIER = args.budget

    if args.local:
        os.environ["AGENT_LOCAL"] = "1"
        import config as _cfg
        _cfg.USE_LOCAL_MODELS = True

    if args.autonomy:
        os.environ["AGENT_AUTONOMY"] = args.autonomy
        import executor as _exe
        _exe.AUTONOMY = args.autonomy

        # full autonomy → use performance models unless user explicitly capped budget
        if args.autonomy == "full" and not args.budget:
            os.environ["AGENT_BUDGET"] = "performance"
            import config as _cfg
            _cfg.BUDGET_TIER = "performance"
            print("[agent] Autonomy=full: budget auto-upgraded to performance")

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
