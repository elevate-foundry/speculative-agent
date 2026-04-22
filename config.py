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

# Free OpenRouter models known to be reliable for agentic tasks.
# These are :free tier models — no cost per token.
_DEFAULT_OPENROUTER_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "deepseek/deepseek-r1:free",
    "google/gemma-3-27b-it:free",
    "qwen/qwen3-235b-a22b:free",
    "mistralai/mistral-7b-instruct:free",
]

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
    provider: str = "ollama"   # "ollama" or "openrouter"
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
    """Fetch all free models from OpenRouter and filter to our curated list."""
    if not OPENROUTER_API_KEY:
        return []
    env_override = os.environ.get("OPENROUTER_MODELS", "").strip()
    wanted = (
        [m.strip() for m in env_override.split(",") if m.strip()]
        if env_override else _DEFAULT_OPENROUTER_MODELS
    )
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{OPENROUTER_BASE}/models",
                headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"},
            )
            resp.raise_for_status()
            data = resp.json()
            available = {m["id"] for m in data.get("data", [])}
            models = []
            for name in wanted:
                if name in available:
                    models.append(ModelInfo(name=name, size_gb=0.0, provider="openrouter"))
            return models
    except Exception as e:
        print(f"  [openrouter] Could not fetch models: {e}")
        return []


async def warmup_openrouter_model(model: ModelInfo) -> ModelInfo:
    """Ping OpenRouter with a 1-token request to confirm the model is live."""
    import time
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            payload = {
                "model": model.name,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
                "stream": False,
            }
            resp = await client.post(
                f"{OPENROUTER_BASE}/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "HTTP-Referer": "https://github.com/elevate-foundry/speculative-agent",
                    "X-Title": "speculative-agent",
                },
                json=payload,
            )
            resp.raise_for_status()
        model.warmed = True
        model.warm_latency_ms = (time.perf_counter() - t0) * 1000
    except Exception as e:
        model.warmed = False
        print(f"  [warmup/openrouter] {model.name} FAILED: {e}")
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
            tag = f"☁ openrouter" if m.provider == "openrouter" else f"{m.size_gb:.1f} GB  local"
            print(f"  ✓ {m.name:<45} {tag} — warmed in {m.warm_latency_ms:.0f}ms")
        for m in dead:
            print(f"  ✗ {m.name} — failed to warm")

    if not live:
        raise RuntimeError("All models failed warmup.")

    return live, hw
