"""
supervisor.py — Real-time stream monitor for parallel speculative CoT.

Watches multiple model streams simultaneously. Scores each model's
reasoning as tokens arrive. Can short-circuit remaining models when
a winner is confident enough.
"""

import asyncio
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional, AsyncIterator
from executor import Action, parse_action_from_text

# ANSI color palette — one per model slot (cycles if >8 models)
_COLORS = [
    "\033[36m",   # cyan
    "\033[33m",   # yellow
    "\033[35m",   # magenta
    "\033[32m",   # green
    "\033[34m",   # blue
    "\033[91m",   # bright red
    "\033[96m",   # bright cyan
    "\033[93m",   # bright yellow
]
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"

_MODEL_COLORS: dict[str, str] = {}


# Confidence threshold to short-circuit other models
SHORT_CIRCUIT_THRESHOLD = 0.85

# Minimum tokens a model must emit before it can be considered for short-circuit
MIN_TOKENS_FOR_SHORTCIRCUIT = 40


@dataclass
class ModelStream:
    model_name: str
    tokens: list[str] = field(default_factory=list)
    done: bool = False
    cancelled: bool = False
    action: Optional[Action] = None
    confidence_history: list[float] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: Optional[str] = None

    @property
    def text(self) -> str:
        return "".join(self.tokens)

    @property
    def token_count(self) -> int:
        return len(self.tokens)


def score_reasoning(text: str) -> float:
    """
    Heuristic confidence score for a model's reasoning so far.
    Range: 0.0 – 1.0
    Factors: action JSON present, explicit confidence value, reasoning keywords.
    """
    score = 0.0

    # Has a well-formed action block
    if re.search(r'"action_type"\s*:', text):
        score += 0.3
    if re.search(r'"confidence"\s*:\s*0\.[89]\d*', text):
        score += 0.25
    elif re.search(r'"confidence"\s*:\s*1\.0', text):
        score += 0.35

    # Reasoning quality signals
    reasoning_keywords = [
        "because", "therefore", "step", "first", "then",
        "reasoning", "plan", "observe", "result", "will",
    ]
    hits = sum(1 for kw in reasoning_keywords if kw in text.lower())
    score += min(hits * 0.04, 0.25)

    # Has a closing ``` (complete action block)
    if text.count("```") >= 2:
        score += 0.15

    return min(score, 1.0)


def _assign_colors(model_names: list[str]) -> None:
    """Assign a stable ANSI color to each model name."""
    for i, name in enumerate(model_names):
        if name not in _MODEL_COLORS:
            _MODEL_COLORS[name] = _COLORS[i % len(_COLORS)]


def _model_label(model_name: str) -> str:
    color = _MODEL_COLORS.get(model_name, "")
    short = model_name.split(":")[0].split("/")[-1][:16]
    return f"{color}{_BOLD}[{short}]{_RESET}"


async def stream_model(
    model_name: str,
    prompt: str,
    stream_obj: ModelStream,
    cancel_event: asyncio.Event,
    ollama_base: str = "http://localhost:11434",
    system_prompt: str = "",
    live_output: bool = True,
) -> None:
    import httpx
    import json as _json

    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": True,
        "system": system_prompt,
        "options": {"temperature": 0.3, "num_predict": 512},
    }

    label = _model_label(model_name)
    color = _MODEL_COLORS.get(model_name, "")

    t0 = time.perf_counter()
    if live_output:
        print(f"\n{label} starting...")
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream("POST", f"{ollama_base}/api/generate", json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if cancel_event.is_set():
                        stream_obj.cancelled = True
                        break
                    if not line.strip():
                        continue
                    try:
                        chunk = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    token = chunk.get("response", "")
                    stream_obj.tokens.append(token)

                    if live_output and token:
                        sys.stdout.write(f"{color}{token}{_RESET}")
                        sys.stdout.flush()

                    if chunk.get("done", False):
                        stream_obj.done = True
                        break
    except asyncio.CancelledError:
        stream_obj.cancelled = True
    except Exception as e:
        stream_obj.error = str(e)
        stream_obj.done = True
    finally:
        stream_obj.elapsed_ms = (time.perf_counter() - t0) * 1000
        stream_obj.done = True
        if live_output:
            elapsed = stream_obj.elapsed_ms
            status = "CANCELLED" if stream_obj.cancelled else "DONE"
            print(f"\n{label} {_DIM}{status} ({elapsed:.0f}ms){_RESET}")


async def supervise_race(
    model_names: list[str],
    prompt: str,
    system_prompt: str,
    ollama_base: str = "http://localhost:11434",
    verbose: bool = True,
    live_output: bool = True,
) -> tuple[Optional[Action], list[ModelStream]]:
    """
    Run all models in parallel. Monitor streams. Short-circuit if any
    model reaches SHORT_CIRCUIT_THRESHOLD confidence early.
    Returns the winning Action and all stream objects for inspection.
    """
    _assign_colors(model_names)
    cancel_event = asyncio.Event()
    streams = {name: ModelStream(model_name=name) for name in model_names}

    tasks = {
        name: asyncio.create_task(
            stream_model(name, prompt, streams[name], cancel_event, ollama_base, system_prompt,
                         live_output=live_output)
        )
        for name in model_names
    }

    winner: Optional[Action] = None
    winning_stream: Optional[ModelStream] = None

    if verbose:
        print(f"\n[supervisor] Racing {len(model_names)} model(s) — watching live...\n")

    try:
        while not all(s.done or s.cancelled for s in streams.values()):
            await asyncio.sleep(0.15)

            for name, s in streams.items():
                if s.done or s.cancelled or s.token_count < MIN_TOKENS_FOR_SHORTCIRCUIT:
                    continue

                score = score_reasoning(s.text)
                s.confidence_history.append(score)

                if verbose and s.token_count % 20 == 0:
                    print(f"  [{name}] tokens={s.token_count} score={score:.2f}")

                if score >= SHORT_CIRCUIT_THRESHOLD and winner is None:
                    action = parse_action_from_text(s.text, name)
                    if action:
                        winner = action
                        winning_stream = s
                        if verbose:
                            print(f"\n[supervisor] SHORT-CIRCUIT: {name} won at "
                                  f"{score:.0%} confidence after {s.token_count} tokens "
                                  f"({s.elapsed_ms:.0f}ms)")
                        cancel_event.set()
                        break

            if cancel_event.is_set():
                break

    except asyncio.CancelledError:
        cancel_event.set()
        raise
    finally:
        cancel_event.set()
        for t in tasks.values():
            t.cancel()
        await asyncio.gather(*tasks.values(), return_exceptions=True)

    # No early winner — pick best action from completed streams
    if winner is None:
        candidates = []
        for s in streams.values():
            if s.text:
                action = parse_action_from_text(s.text, s.model_name)
                if action:
                    candidates.append((action, score_reasoning(s.text), s.elapsed_ms))

        if candidates:
            # Rank by confidence score, then by speed
            candidates.sort(key=lambda x: (-x[1], x[2]))
            winner, best_score, best_ms = candidates[0]
            if verbose:
                print(f"\n[supervisor] Winner (post-race): {winner.model_source} "
                      f"score={best_score:.2f} latency={best_ms:.0f}ms")

    return winner, list(streams.values())


def print_race_summary(streams: list[ModelStream]) -> None:
    print("\n" + "═" * 60)
    print("  RACE SUMMARY")
    print("─" * 60)
    for s in streams:
        status = "CANCELLED" if s.cancelled else ("DONE" if s.done else "RUNNING")
        score = score_reasoning(s.text) if s.text else 0.0
        err = f" ERR:{s.error}" if s.error else ""
        print(f"  {s.model_name:<30} {status:<10} "
              f"tokens={s.token_count:<5} score={score:.2f} "
              f"{s.elapsed_ms:.0f}ms{err}")
    print("═" * 60)
