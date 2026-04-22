#!/usr/bin/env python3
"""
benchmark.py — Horse-race model evaluation via repeated parallel sampling.

Runs a golden test suite N times in parallel across all active models,
measures win rates, latency distributions, and action quality, then
persists results to ~/.agent_stats.json for UCB1 provider selection.

Usage:
    python benchmark.py                     # run default suite, 10 rounds
    python benchmark.py --rounds 50         # more rounds = tighter confidence intervals
    python benchmark.py --suite coding      # specific test suite
    python benchmark.py --show              # print current stats table and exit

Wall-clock time = time of ONE sequential run (all rounds are parallel).
"""

import asyncio
import argparse
import json
import math
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from config import discover_and_warmup, ModelInfo
from supervisor import supervise_race, score_reasoning
from executor import parse_action_from_text

STATS_FILE = os.path.expanduser("~/.agent_stats.json")

# ── Golden test suite ──────────────────────────────────────────────────────────
# Each prompt has a ground-truth validator: a function that returns 0.0–1.0
# quality score for a given action output.  Prompts are designed to be
# unambiguous so model quality differences are measurable.

@dataclass
class BenchPrompt:
    name: str
    prompt: str
    suite: str                          # "reasoning", "coding", "tool_use", "mixed"
    validator: str                      # name of validator function below
    system_prompt: str = ""


def _v_bash_present(text: str) -> float:
    """Model should propose a bash action."""
    from executor import parse_action_from_text as _p
    action = _p(text, "eval")
    if action and action.action_type == "bash":
        return 1.0 if action.confidence >= 0.8 else 0.6
    return 0.0


def _v_noop_present(text: str) -> float:
    """Model should emit noop when task is already complete."""
    from executor import parse_action_from_text as _p
    action = _p(text, "eval")
    if action and action.action_type == "noop":
        return 1.0
    return 0.0


def _v_read_file_present(text: str) -> float:
    """Model should propose a read_file action."""
    from executor import parse_action_from_text as _p
    action = _p(text, "eval")
    if action and action.action_type == "read_file":
        return 1.0 if action.confidence >= 0.8 else 0.5
    return 0.0


def _v_write_file_present(text: str) -> float:
    """Model should propose a write_file action."""
    from executor import parse_action_from_text as _p
    action = _p(text, "eval")
    if action and action.action_type == "write_file":
        return 1.0 if action.confidence >= 0.8 else 0.5
    return 0.0


def _v_high_confidence(text: str) -> float:
    """Model should produce high-confidence structured output."""
    return score_reasoning(text)


_VALIDATORS = {
    "bash_present":       _v_bash_present,
    "noop_present":       _v_noop_present,
    "read_file_present":  _v_read_file_present,
    "write_file_present": _v_write_file_present,
    "high_confidence":    _v_high_confidence,
}

_SYSTEM = (
    "You are a machine control agent. For each task, respond with a single JSON "
    "action block in a ```json ... ``` fence with keys: action_type, description, "
    "confidence (0-1), payload. action_type must be one of: bash, python_exec, "
    "write_file, read_file, pyautogui, playwright, noop."
)

SUITES: dict[str, list[BenchPrompt]] = {
    "tool_use": [
        BenchPrompt("date_cmd",     "What is today's date?",
                    "tool_use", "bash_present", _SYSTEM),
        BenchPrompt("list_files",   "List all files in the current directory.",
                    "tool_use", "bash_present", _SYSTEM),
        BenchPrompt("read_readme",  "Read the contents of README.md.",
                    "tool_use", "read_file_present", _SYSTEM),
        BenchPrompt("write_hello",  "Create a file called hello.txt containing 'Hello, world!'.",
                    "tool_use", "write_file_present", _SYSTEM),
        BenchPrompt("task_done",    "The task has already been completed successfully. No further action needed.",
                    "tool_use", "noop_present", _SYSTEM),
    ],
    "reasoning": [
        BenchPrompt("disk_usage",   "Find which directory under /Users is using the most disk space.",
                    "reasoning", "bash_present", _SYSTEM),
        BenchPrompt("process_list", "Show all running processes and their memory usage, sorted by memory.",
                    "reasoning", "bash_present", _SYSTEM),
        BenchPrompt("git_log",      "Show the last 5 git commits with their messages.",
                    "reasoning", "bash_present", _SYSTEM),
    ],
    "coding": [
        BenchPrompt("fib_py",       "Write a Python script that prints the first 20 Fibonacci numbers.",
                    "coding", "write_file_present", _SYSTEM),
        BenchPrompt("json_parse",   "Write a bash one-liner to count the number of keys in a JSON file called data.json.",
                    "coding", "bash_present", _SYSTEM),
    ],
}
SUITES["mixed"] = [p for s in SUITES.values() for p in s]


# ── Per-model statistics ───────────────────────────────────────────────────────

@dataclass
class ModelStats:
    model_name: str
    provider: str
    wins: int = 0           # times this model had the highest quality score in a race
    races: int = 0          # total races participated in
    quality_sum: float = 0.0
    latency_sum_ms: float = 0.0
    errors: int = 0

    @property
    def win_rate(self) -> float:
        return self.wins / self.races if self.races else 0.0

    @property
    def avg_quality(self) -> float:
        return self.quality_sum / max(self.races - self.errors, 1)

    @property
    def avg_latency_ms(self) -> float:
        return self.latency_sum_ms / max(self.races - self.errors, 1)

    def ucb1(self, total_races: int) -> float:
        """UCB1 score — higher = more promising to select next."""
        if self.races == 0:
            return float("inf")
        exploitation = self.avg_quality
        exploration = math.sqrt(2 * math.log(max(total_races, 1)) / self.races)
        return exploitation + exploration


def load_stats() -> dict[str, ModelStats]:
    try:
        with open(STATS_FILE) as f:
            raw = json.load(f)
        return {k: ModelStats(**v) for k, v in raw.items()}
    except (FileNotFoundError, json.JSONDecodeError, TypeError):
        return {}


def save_stats(stats: dict[str, ModelStats]) -> None:
    data = {k: asdict(v) for k, v in stats.items()}
    with open(STATS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def print_stats_table(stats: dict[str, ModelStats]) -> None:
    if not stats:
        print("No benchmark data yet. Run: python benchmark.py")
        return

    total = sum(s.races for s in stats.values())
    rows = sorted(stats.values(), key=lambda s: s.ucb1(total), reverse=True)

    print("\n" + "═" * 80)
    print(f"  MODEL PERFORMANCE TABLE  ({total} total races)")
    print("─" * 80)
    print(f"  {'Model':<35} {'Win%':>5}  {'Qual':>5}  {'Lat(ms)':>8}  {'Races':>6}  {'UCB1':>6}")
    print("─" * 80)
    for s in rows:
        ucb = s.ucb1(total)
        ucb_str = f"{ucb:.3f}" if not math.isinf(ucb) else "  new"
        print(f"  {s.model_name:<35} {s.win_rate:>4.0%}  {s.avg_quality:>5.2f}"
              f"  {s.avg_latency_ms:>8.0f}  {s.races:>6}  {ucb_str:>6}")
    print("═" * 80 + "\n")


# ── Single benchmark race ──────────────────────────────────────────────────────

async def run_benchmark_race(
    prompt: BenchPrompt,
    models: list[ModelInfo],
    round_num: int,
) -> dict[str, tuple[float, float, Optional[str]]]:
    """
    Race all models on a single prompt.
    Returns {model_name: (quality, latency_ms, error_or_None)}.
    """
    _action, streams = await supervise_race(
        model_names=models,
        prompt=prompt.prompt,
        system_prompt=prompt.system_prompt,
        verbose=False,
        live_output=False,
    )

    validator = _VALIDATORS[prompt.validator]
    results = {}
    for s in streams:
        if s.error:
            results[s.model_name] = (0.0, s.elapsed_ms, s.error)
        else:
            quality = validator(s.text)
            results[s.model_name] = (quality, s.elapsed_ms, None)
    return results


# ── Main benchmark loop ────────────────────────────────────────────────────────

async def run_benchmark(
    suite_name: str = "mixed",
    rounds: int = 10,
    verbose: bool = True,
) -> dict[str, ModelStats]:
    models, hw = await discover_and_warmup(verbose=verbose)
    stats = load_stats()

    # Ensure stats entry for every model
    for m in models:
        if m.name not in stats:
            stats[m.name] = ModelStats(model_name=m.name, provider=m.provider)

    prompts = SUITES.get(suite_name, SUITES["mixed"])
    total_races = len(prompts) * rounds

    print(f"\n[bench] Suite={suite_name!r}  prompts={len(prompts)}  "
          f"rounds={rounds}  total_races={total_races}")
    print(f"[bench] Models: {[m.name.split('/')[-1] for m in models]}")
    print(f"[bench] Wall-clock time ≈ time of {rounds} sequential runs\n")

    t_start = time.perf_counter()
    completed = 0

    for round_num in range(1, rounds + 1):
        # Run all prompts in this round concurrently — same wall time as one
        race_tasks = [
            run_benchmark_race(p, models, round_num)
            for p in prompts
        ]
        round_results = await asyncio.gather(*race_tasks)

        for prompt, race_result in zip(prompts, round_results):
            # Find winner (highest quality, ties broken by latency)
            valid = {k: v for k, v in race_result.items() if v[2] is None}
            winner_name = max(valid, key=lambda k: (valid[k][0], -valid[k][1])) if valid else None

            for model_name, (quality, latency_ms, error) in race_result.items():
                s = stats[model_name]
                s.races += 1
                if error:
                    s.errors += 1
                else:
                    s.quality_sum += quality
                    s.latency_sum_ms += latency_ms
                    if model_name == winner_name:
                        s.wins += 1

        completed += len(prompts)
        elapsed = time.perf_counter() - t_start
        pct = completed / total_races * 100
        print(f"  Round {round_num}/{rounds}  ({pct:.0f}%)  elapsed={elapsed:.1f}s", end="\r")
        save_stats(stats)  # checkpoint after each round

    print(f"\n[bench] Done in {time.perf_counter() - t_start:.1f}s\n")
    print_stats_table(stats)
    return stats


# ── CLI ────────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Benchmark model racing performance")
    parser.add_argument("--rounds", type=int, default=10,
                        help="Number of rounds per prompt (default 10)")
    parser.add_argument("--suite", choices=list(SUITES.keys()), default="mixed",
                        help="Test suite to run (default: mixed)")
    parser.add_argument("--show", action="store_true",
                        help="Print current stats table and exit")
    parser.add_argument("--reset", action="store_true",
                        help="Clear all accumulated stats")
    args = parser.parse_args()

    if args.reset:
        if os.path.exists(STATS_FILE):
            os.unlink(STATS_FILE)
        print("Stats reset.")
        return

    if args.show:
        print_stats_table(load_stats())
        return

    await run_benchmark(suite_name=args.suite, rounds=args.rounds)


if __name__ == "__main__":
    asyncio.run(main())
