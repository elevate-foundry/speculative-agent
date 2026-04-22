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

# Session-level 429 blacklist: model_name -> consecutive 429 count
# A single 429 blacklists a model; the agent then replaces it from the full pool.
_RATE_LIMITED: dict[str, int] = {}
_RATE_LIMIT_THRESHOLD = 1


# Confidence threshold to short-circuit other models
SHORT_CIRCUIT_THRESHOLD = 0.85

# Minimum tokens a model must emit before it can be considered for short-circuit
MIN_TOKENS_FOR_SHORTCIRCUIT = 40


@dataclass
class ModelStream:
    model_name: str
    provider: str = "ollama"   # "ollama" or "openrouter"
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


def _model_label(model_name: str, provider: str = "ollama") -> str:
    color = _MODEL_COLORS.get(model_name, "")
    short = model_name.split(":")[0].split("/")[-1][:16]
    cloud = "☁" if provider == "openrouter" else "⬡"
    return f"{color}{_BOLD}{cloud}[{short}]{_RESET}"


async def _stream_ollama(
    model_name: str,
    prompt: str,
    system_prompt: str,
    stream_obj: ModelStream,
    cancel_event: asyncio.Event,
    ollama_base: str,
    color: str,
    live_output: bool,
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
    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream("POST", f"{ollama_base}/api/generate", json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if cancel_event.is_set():
                    stream_obj.cancelled = True
                    return
                if not line.strip():
                    continue
                try:
                    chunk = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                token = chunk.get("response", "")
                if token:
                    stream_obj.tokens.append(token)
                if chunk.get("done", False):
                    stream_obj.done = True
                    return


async def _stream_openrouter(
    model_name: str,
    prompt: str,
    system_prompt: str,
    stream_obj: ModelStream,
    cancel_event: asyncio.Event,
    color: str,
    live_output: bool,
    screenshot_b64: Optional[str] = None,
    max_tokens: int = 1024,
) -> None:
    import httpx
    import json as _json
    from config import OPENROUTER_BASE, OPENROUTER_API_KEY

    # Build user message — include screenshot for vision-capable models
    if screenshot_b64:
        user_content = [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {
                "url": f"data:image/png;base64,{screenshot_b64}"
            }},
        ]
    else:
        user_content = prompt

    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_content},
        ],
        "stream": True,
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "HTTP-Referer": "https://github.com/elevate-foundry/speculative-agent",
        "X-Title": "speculative-agent",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream("POST", f"{OPENROUTER_BASE}/chat/completions",
                                 json=payload, headers=headers) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if cancel_event.is_set():
                    stream_obj.cancelled = True
                    return
                if not line.startswith("data: "):
                    continue
                data = line[6:].strip()
                if data == "[DONE]":
                    stream_obj.done = True
                    return
                try:
                    chunk = _json.loads(data)
                except _json.JSONDecodeError:
                    continue
                delta = chunk.get("choices", [{}])[0].get("delta", {})
                token = delta.get("content", "")
                if token:
                    stream_obj.tokens.append(token)
                finish = chunk.get("choices", [{}])[0].get("finish_reason")
                if finish and finish != "null":
                    stream_obj.done = True
                    return


async def _stream_direct(
    model_name: str,
    prompt: str,
    system_prompt: str,
    stream_obj: ModelStream,
    cancel_event: asyncio.Event,
    color: str,
    live_output: bool,
    provider_config: object,
    screenshot_b64: Optional[str] = None,
    max_tokens: int = 1024,
) -> None:
    """Stream from a direct provider API. Supports both OpenAI-compat and native Anthropic /v1/messages."""
    import httpx
    import json as _json

    prov = provider_config  # type: ignore
    auth_value = f"{prov.auth_prefix} {prov.api_key}".strip() if prov.auth_prefix else prov.api_key
    headers = {prov.auth_header: auth_value, **prov.extra_headers}

    # ── Anthropic native /v1/messages SSE ──────────────────────────────────
    if getattr(prov, "use_messages_api", False):
        if screenshot_b64:
            user_content = [
                {"type": "text", "text": prompt},
                {"type": "image", "source": {
                    "type": "base64", "media_type": "image/png",
                    "data": screenshot_b64,
                }},
            ]
        else:
            user_content = prompt

        payload = {
            "model": model_name,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_content}],
            "stream": True,
            "max_tokens": max_tokens,
        }
        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST", f"{prov.base_url}/messages",
                json=payload, headers=headers
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if cancel_event.is_set():
                        stream_obj.cancelled = True
                        return
                    if not line.startswith("data: "):
                        continue
                    data = line[6:].strip()
                    if not data:
                        continue
                    try:
                        chunk = _json.loads(data)
                    except _json.JSONDecodeError:
                        continue
                    etype = chunk.get("type", "")
                    if etype == "content_block_delta":
                        token = chunk.get("delta", {}).get("text", "")
                        if token:
                            stream_obj.tokens.append(token)
                    elif etype == "message_stop":
                        stream_obj.done = True
                        return
                    elif etype == "message_delta":
                        reason = chunk.get("delta", {}).get("stop_reason")
                        if reason:
                            stream_obj.done = True
                            return
        return

    # ── OpenAI-compatible /chat/completions SSE ────────────────────────────
    if screenshot_b64:
        user_content = [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {
                "url": f"data:image/png;base64,{screenshot_b64}"
            }},
        ]
    else:
        user_content = prompt

    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_content},
        ],
        "stream": True,
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }

    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream(
            "POST", f"{prov.base_url}/chat/completions",
            json=payload, headers=headers
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if cancel_event.is_set():
                    stream_obj.cancelled = True
                    return
                if not line.startswith("data: "):
                    continue
                data = line[6:].strip()
                if data == "[DONE]":
                    stream_obj.done = True
                    return
                try:
                    chunk = _json.loads(data)
                except _json.JSONDecodeError:
                    continue
                delta = chunk.get("choices", [{}])[0].get("delta", {})
                token = delta.get("content", "")
                if token:
                    stream_obj.tokens.append(token)
                finish = chunk.get("choices", [{}])[0].get("finish_reason")
                if finish and finish != "null" and finish is not None:
                    stream_obj.done = True
                    return


async def stream_model(
    model_name: str,
    prompt: str,
    stream_obj: ModelStream,
    cancel_event: asyncio.Event,
    ollama_base: str = "http://localhost:11434",
    system_prompt: str = "",
    live_output: bool = True,
    screenshot_b64: Optional[str] = None,
    provider_config: object = None,
    max_tokens: int = 1024,
) -> None:
    label = _model_label(model_name, stream_obj.provider)
    color = _MODEL_COLORS.get(model_name, "")

    # Skip models blacklisted by a 429 — agent will replace them
    if _RATE_LIMITED.get(model_name, 0) >= _RATE_LIMIT_THRESHOLD:
        stream_obj.error = "rate-limited — will be replaced"
        stream_obj.done = True
        return

    t0 = time.perf_counter()
    if live_output:
        print(f"\n{label} starting...")
    try:
        if provider_config is not None:
            await _stream_direct(model_name, prompt, system_prompt,
                                 stream_obj, cancel_event, color, live_output,
                                 provider_config, screenshot_b64=screenshot_b64,
                                 max_tokens=max_tokens)
        elif stream_obj.provider == "openrouter":
            await _stream_openrouter(model_name, prompt, system_prompt,
                                     stream_obj, cancel_event, color, live_output,
                                     screenshot_b64=screenshot_b64,
                                     max_tokens=max_tokens)
        else:
            await _stream_ollama(model_name, prompt, system_prompt,
                                 stream_obj, cancel_event, ollama_base, color, live_output)
    except asyncio.CancelledError:
        stream_obj.cancelled = True
    except Exception as e:
        err = str(e)
        stream_obj.error = err
        # Track 429s for blacklisting
        if "429" in err:
            _RATE_LIMITED[model_name] = _RATE_LIMITED.get(model_name, 0) + 1
            if _RATE_LIMITED[model_name] >= _RATE_LIMIT_THRESHOLD:
                print(f"\n{label} ⚠ rate-limited {_RATE_LIMIT_THRESHOLD}x — dropping from session pool")
        else:
            _RATE_LIMITED[model_name] = 0  # reset on non-429 error
        stream_obj.done = True
    finally:
        stream_obj.elapsed_ms = (time.perf_counter() - t0) * 1000
        stream_obj.done = True
        if live_output:
            status = "CANCELLED" if stream_obj.cancelled else "DONE"
            print(f"\n{label} {_DIM}{status} ({stream_obj.elapsed_ms:.0f}ms){_RESET}")


async def supervise_race(
    model_names: "list[str] | list",
    prompt: str,
    system_prompt: str,
    ollama_base: str = "http://localhost:11434",
    verbose: bool = True,
    live_output: bool = True,
    screenshot_b64: Optional[str] = None,
    max_tokens: int = 1024,
) -> tuple[Optional[Action], list[ModelStream]]:
    """
    Run all models in parallel. Monitor streams. Short-circuit if any
    model reaches SHORT_CIRCUIT_THRESHOLD confidence early.
    Accepts either a list of model name strings or ModelInfo objects.
    Returns the winning Action and all stream objects for inspection.
    """
    # Normalise: accept both plain strings and ModelInfo objects
    from config import ModelInfo as _ModelInfo
    models_info: list[_ModelInfo] = [
        m if isinstance(m, _ModelInfo) else _ModelInfo(name=m, size_gb=0.0, provider="ollama")
        for m in model_names
    ]
    names = [m.name for m in models_info]

    _assign_colors(names)
    cancel_event = asyncio.Event()
    streams = {m.name: ModelStream(model_name=m.name, provider=m.provider) for m in models_info}

    tasks = {
        m.name: asyncio.create_task(
            stream_model(m.name, prompt, streams[m.name], cancel_event, ollama_base, system_prompt,
                         live_output=live_output, screenshot_b64=screenshot_b64,
                         provider_config=getattr(m, "provider_config", None),
                         max_tokens=max_tokens))
        for m in models_info
    }

    winner: Optional[Action] = None
    winning_stream: Optional[ModelStream] = None

    if verbose:
        print(f"\n[supervisor] Racing {len(model_names)} model(s)...\n")

    _dashboard_lines = 0  # track how many lines the dashboard occupies

    def _redraw_dashboard() -> None:
        nonlocal _dashboard_lines
        # Move cursor up to overwrite previous dashboard
        if _dashboard_lines > 0:
            sys.stdout.write(f"\033[{_dashboard_lines}A")
        lines = []
        for s in streams.values():
            color = _MODEL_COLORS.get(s.model_name, "")
            short = s.model_name.split(":")[0].split("/")[-1][:18]
            if s.error:
                state = f"\033[91m✗ ERR\033[0m"
            elif s.cancelled:
                state = f"\033[2m✗ cancel\033[0m"
            elif s.done:
                score = score_reasoning(s.text)
                state = f"\033[32m✓ {s.elapsed_ms:.0f}ms  score={score:.2f}\033[0m"
            else:
                # Show last ~40 chars of partial output
                snippet = s.text.replace("\n", " ")[-40:].strip()
                state = f"\033[2m{s.token_count:>3}tok  {snippet}\033[0m"
            lines.append(f"  {color}{short:<20}\033[0m  {state}")
        output = "\n".join(lines) + "\n"
        sys.stdout.write(output)
        sys.stdout.flush()
        _dashboard_lines = len(lines)

    try:
        while not all(s.done or s.cancelled for s in streams.values()):
            await asyncio.sleep(0.30)

            if verbose:
                _redraw_dashboard()

            for name, s in streams.items():
                if s.done or s.cancelled or s.token_count < MIN_TOKENS_FOR_SHORTCIRCUIT:
                    continue

                score = score_reasoning(s.text)
                s.confidence_history.append(score)

                if score >= SHORT_CIRCUIT_THRESHOLD and winner is None:
                    action = parse_action_from_text(s.text, name)
                    if action:
                        winner = action
                        winning_stream = s
                        if verbose:
                            _redraw_dashboard()
                            print(f"\n[supervisor] ⚡ SHORT-CIRCUIT: {name} "
                                  f"{score:.0%} confidence  {s.token_count} tok  "
                                  f"{s.elapsed_ms:.0f}ms")
                        cancel_event.set()
                        break

            if cancel_event.is_set():
                break

        if verbose:
            _redraw_dashboard()  # final redraw showing all done

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

    # Record production race outcomes into benchmark stats (passive learning)
    try:
        from benchmark import load_stats, save_stats, ModelStats
        bstats = load_stats()
        for s in streams.values():
            if s.model_name not in bstats:
                bstats[s.model_name] = ModelStats(
                    model_name=s.model_name, provider=s.provider)
            ms = bstats[s.model_name]
            ms.races += 1
            if s.error:
                ms.errors += 1
            else:
                quality = score_reasoning(s.text) if s.text else 0.0
                ms.quality_sum += quality
                ms.latency_sum_ms += s.elapsed_ms
                if winner and s.model_name == winner.model_source:
                    ms.wins += 1
        save_stats(bstats)
    except Exception:
        pass  # never let stats recording break the agent

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
