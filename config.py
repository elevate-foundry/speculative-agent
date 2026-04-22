"""
config.py — Hardware-aware model detection and warmup.
Auto-discovers locally pulled Ollama models AND free OpenRouter models.
Limits local concurrency to available CPU/GPU resources.
Set OPENROUTER_API_KEY env var to enable OpenRouter models.
"""

import os
import json
import math
import multiprocessing
import subprocess
import httpx
import asyncio
from dataclasses import dataclass, field
from typing import Optional

OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OPENROUTER_BASE = "https://openrouter.ai/api/v1"
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

# Max number of OpenRouter free models to include in the race.
# They are ranked by context window size (larger = better for agentic tasks).
OPENROUTER_MAX_MODELS = int(os.environ.get("OPENROUTER_MAX_MODELS", "5"))

# Models to include in the race. Override with AGENT_MODELS env var (comma-separated).
# Defaults to a hand-picked set balancing speed, reasoning, and code ability.
_DEFAULT_RACE_MODELS = [
    "llama3.2:1b",
    "distilled-phi3.5:latest",
    "gemma3:4b",
    "qwen2.5-coder:latest",
    "deepseek-r1:latest",
]

def get_race_allowlist() -> list[str] | None:
    env = os.environ.get("AGENT_MODELS", "").strip()
    if env:
        return [m.strip() for m in env.split(",") if m.strip()]
    return _DEFAULT_RACE_MODELS


@dataclass
class HardwareProfile:
    cpu_cores: int
    cpu_logical: int
    ram_gb: float
    gpu_vram_gb: float
    max_parallel_models: int


@dataclass
class ModelInfo:
    name: str
    size_gb: float
    provider: str = "ollama"       # "ollama" or "openrouter"
    context_length: int = 0        # token context window (openrouter)
    cost_per_token: float = 0.0    # prompt cost USD/token (0.0 = free)
    warmed: bool = False
    warm_latency_ms: Optional[float] = None


def detect_hardware() -> HardwareProfile:
    cpu_cores = multiprocessing.cpu_count()
    try:
        import psutil
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
        cpu_logical = psutil.cpu_count(logical=True)
    except ImportError:
        ram_gb = 8.0
        cpu_logical = cpu_cores

    gpu_vram_gb = _detect_gpu_vram()

    # Conservative: leave 2 cores and 2 GB RAM for the OS
    usable_ram = max(ram_gb - 2.0, 1.0)
    # Assume average model needs ~4 GB; cap at logical cores / 2
    by_ram = max(1, math.floor(usable_ram / 4.0))
    by_cpu = max(1, cpu_logical // 2)
    by_gpu = max(1, math.floor(gpu_vram_gb / 4.0)) if gpu_vram_gb > 0 else by_ram
    max_parallel = min(by_ram, by_cpu, by_gpu if gpu_vram_gb > 0 else by_ram)

    return HardwareProfile(
        cpu_cores=cpu_cores,
        cpu_logical=cpu_logical,
        ram_gb=ram_gb,
        gpu_vram_gb=gpu_vram_gb,
        max_parallel_models=max_parallel,
    )


def _detect_gpu_vram() -> float:
    # Try nvidia-smi
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        mb = sum(int(x.strip()) for x in out.decode().strip().splitlines() if x.strip().isdigit())
        return mb / 1024.0
    except Exception:
        pass
    # Try macOS Metal via system_profiler
    try:
        out = subprocess.check_output(
            ["system_profiler", "SPDisplaysDataType"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode()
        for line in out.splitlines():
            if "VRAM" in line or "vram" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[1].strip().split()[0]
                    mult = 1.0
                    if "MB" in parts[1]:
                        mult = 1 / 1024.0
                    try:
                        return float(val) * mult
                    except ValueError:
                        pass
    except Exception:
        pass
    return 0.0


async def list_local_models() -> list[ModelInfo]:
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = []
            for m in data.get("models", []):
                size_bytes = m.get("size", 0)
                models.append(ModelInfo(
                    name=m["name"],
                    size_gb=size_bytes / (1024 ** 3),
                    provider="ollama",
                ))
            return models
        except Exception as e:
            raise RuntimeError(f"Cannot reach Ollama at {OLLAMA_BASE}: {e}")


async def list_openrouter_models() -> list[ModelInfo]:
    """
    Auto-discover free OpenRouter models.
    If OPENROUTER_MODELS env var is set, use that list (comma-separated).
    Otherwise fetch all models from the API, keep only :free ones,
    and rank by context_length descending (larger context = better for agents).
    Caps at OPENROUTER_MAX_MODELS.
    """
    if not OPENROUTER_API_KEY:
        return []

    env_override = os.environ.get("OPENROUTER_MODELS", "").strip()

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{OPENROUTER_BASE}/models",
                headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"},
            )
            resp.raise_for_status()
            data = resp.json()

        all_models = data.get("data", [])

        if env_override:
            wanted = {m.strip() for m in env_override.split(",") if m.strip()}
            candidates = [m for m in all_models if m["id"] in wanted]
        else:
            # Keep only genuinely free models (prompt cost == 0)
            candidates = [
                m for m in all_models
                if ":free" in m["id"]
                or float((m.get("pricing") or {}).get("prompt", "1") or "1") == 0.0
            ]

        # Rank by context_length descending — more context = more useful for agents
        candidates.sort(key=lambda m: int(m.get("context_length") or 0), reverse=True)

        # Cap to max
        candidates = candidates[:OPENROUTER_MAX_MODELS]

        models = []
        for m in candidates:
            pricing = m.get("pricing") or {}
            cost = float(pricing.get("prompt", "0") or "0")
            ctx = int(m.get("context_length") or 0)
            models.append(ModelInfo(
                name=m["id"],
                size_gb=0.0,
                provider="openrouter",
                context_length=ctx,
                cost_per_token=cost,
            ))

        return models

    except Exception as e:
        print(f"  [openrouter] Could not fetch models: {e}")
        return []


async def warmup_openrouter_model(model: ModelInfo) -> ModelInfo:
    """
    OpenRouter warmup: no live ping (avoids 429 rate limits on free tier).
    The model was already confirmed to exist in list_openrouter_models().
    We mark it as warmed immediately with a nominal latency.
    """
    model.warmed = True
    model.warm_latency_ms = 0.0
    return model


async def warmup_model(model: ModelInfo, semaphore: asyncio.Semaphore) -> ModelInfo:
    """Send a minimal prompt to ensure the model is loaded into memory."""
    if model.provider == "openrouter":
        return await warmup_openrouter_model(model)
    async with semaphore:
        import time
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                payload = {
                    "model": model.name,
                    "prompt": "ping",
                    "stream": False,
                    "options": {"num_predict": 1},
                }
                resp = await client.post(f"{OLLAMA_BASE}/api/generate", json=payload)
                resp.raise_for_status()
            elapsed_ms = (time.perf_counter() - t0) * 1000
            model.warmed = True
            model.warm_latency_ms = elapsed_ms
        except Exception as e:
            model.warmed = False
            model.warm_latency_ms = None
            print(f"  [warmup] {model.name} FAILED: {e}")
        return model


async def discover_and_warmup(verbose: bool = True) -> tuple[list[ModelInfo], HardwareProfile]:
    hw = detect_hardware()
    if verbose:
        print(f"[config] Hardware: {hw.cpu_logical} logical CPUs, "
              f"{hw.ram_gb:.1f} GB RAM, "
              f"{hw.gpu_vram_gb:.1f} GB GPU VRAM "
              f"→ max {hw.max_parallel_models} parallel models")

    # --- Ollama local models ---
    all_local = await list_local_models()
    if not all_local and not OPENROUTER_API_KEY:
        raise RuntimeError("No Ollama models found and no OPENROUTER_API_KEY set.")

    allowlist = get_race_allowlist()
    if allowlist:
        available_names = {m.name for m in all_local}
        local_models = [m for m in all_local if m.name in allowlist]
        missing = [n for n in allowlist if n not in available_names]
        if missing and verbose:
            print(f"[config] Skipping (not pulled): {missing}")
    else:
        local_models = all_local

    # --- OpenRouter cloud models ---
    or_models = []
    if OPENROUTER_API_KEY:
        if verbose:
            print("[config] OPENROUTER_API_KEY detected — fetching free cloud models...")
        or_models = await list_openrouter_models()
        if verbose and or_models:
            print(f"[config] OpenRouter free models: {[m.name for m in or_models]}")
    else:
        if verbose:
            print("[config] No OPENROUTER_API_KEY — skipping cloud models (set it to add free cloud racing)")

    all_models = local_models + or_models
    if not all_models:
        raise RuntimeError("No models available. Pull an Ollama model or set OPENROUTER_API_KEY.")

    if verbose:
        print(f"[config] Warming up {len(all_models)} model(s)...")

    sem = asyncio.Semaphore(hw.max_parallel_models)
    warmed = await asyncio.gather(*[warmup_model(m, sem) for m in all_models])

    live = [m for m in warmed if m.warmed]
    dead = [m for m in warmed if not m.warmed]

    if verbose:
        for m in live:
            if m.provider == "openrouter":
                ctx_str = f"{m.context_length//1000}k ctx" if m.context_length else "?k ctx"
                tag = f"☁ openrouter  {ctx_str}  free"
            else:
                tag = f"⬡ local       {m.size_gb:.1f} GB"
            warmup = "(catalog)" if m.provider == "openrouter" else f"{m.warm_latency_ms:.0f}ms"
            print(f"  ✓ {m.name:<50} {tag}  warmup={warmup}")
        for m in dead:
            print(f"  ✗ {m.name} — failed to warm")

    if not live:
        raise RuntimeError("All models failed warmup.")

    return live, hw
