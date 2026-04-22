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

# Max number of OpenRouter models to include in the race.
OPENROUTER_MAX_MODELS = int(os.environ.get("OPENROUTER_MAX_MODELS", "5"))

# Budget tiers — controls which paid models are added to the race pool.
# free       : only :free models (default)
# standard   : adds fast/cheap paid models (~$0.0002/tok)
# performance: adds top-tier models with vision (~$0.005/tok)
BUDGET_TIER = os.environ.get("AGENT_BUDGET", "free").lower()

# Curated paid model lists per tier (OpenRouter IDs)
_STANDARD_MODELS = [
    "openai/gpt-4o-mini",
    "anthropic/claude-haiku-20240307",
    "google/gemini-flash-1.5",
    "mistralai/mistral-small-3.1-24b-instruct",
]

_PERFORMANCE_MODELS = [
    "openai/gpt-4o",
    "anthropic/claude-sonnet-4",
    "google/gemini-2.5-pro-preview",
    "openai/o3",
]

# Keywords that signal the task needs a higher tier
_VISION_KEYWORDS = [
    "screenshot", "screen", "look at", "what do you see", "what's on",
    "click", "find the button", "read the page", "what is shown",
]
_SPEED_KEYWORDS = [
    "fast", "quickly", "urgent", "asap", "immediately", "right now",
    "hurry", "speed", "instant",
]
_COMPLEX_KEYWORDS = [
    "analyze", "write a report", "summarize", "compare", "research",
    "explain in detail", "plan", "strategy", "optimize",
]


def classify_task_tier(task: str) -> str:
    """
    Auto-detect the appropriate budget tier for a task.
    Returns 'free', 'standard', or 'performance'.
    Never upgrades beyond the user's configured BUDGET_TIER.
    When AGENT_AUTONOMY=full, always uses the budget ceiling —
    no task is too simple to deserve the best available model.
    """
    tier_order = ["free", "standard", "performance"]
    ceiling = tier_order.index(BUDGET_TIER)

    # In full autonomy mode, always use the ceiling tier
    if os.environ.get("AGENT_AUTONOMY", "normal") == "full":
        return tier_order[ceiling]

    task_lower = task.lower()
    needs_vision = any(kw in task_lower for kw in _VISION_KEYWORDS)
    needs_speed = any(kw in task_lower for kw in _SPEED_KEYWORDS)
    needs_complex = any(kw in task_lower for kw in _COMPLEX_KEYWORDS)

    if needs_vision or (needs_speed and needs_complex):
        recommended = "performance"
    elif needs_speed or needs_complex:
        recommended = "standard"
    else:
        recommended = "free"

    recommended_idx = tier_order.index(recommended)
    return tier_order[min(recommended_idx, ceiling)]

# Whether to include local Ollama models in the race.
# Default: off when OPENROUTER_API_KEY is set (cloud is faster and stronger),
#          on when no API key (local is the only option).
# Override: AGENT_LOCAL=1 forces local on, AGENT_LOCAL=0 forces it off.
_local_env = os.environ.get("AGENT_LOCAL", "").strip()
if _local_env == "1":
    USE_LOCAL_MODELS = True
elif _local_env == "0":
    USE_LOCAL_MODELS = False
else:
    USE_LOCAL_MODELS = not bool(OPENROUTER_API_KEY)  # off if cloud available

# Tasks containing these keywords are always routed to local models only,
# regardless of USE_LOCAL_MODELS, to avoid sending sensitive data to cloud.
_PRIVATE_KEYWORDS = [
    "password", "secret", "private key", "api key", "token", "credential",
    "ssh", "gpg", "keychain", "wallet", "bank", "social security", "ssn",
    "passport", "medical", "confidential",
]


def is_private_task(task: str) -> bool:
    """Return True if the task contains privacy-sensitive keywords."""
    t = task.lower()
    return any(kw in t for kw in _PRIVATE_KEYWORDS)


# Models to include in the local race. Override with AGENT_MODELS env var.
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
    provider: str = "ollama"       # "ollama", "openrouter", or provider name
    context_length: int = 0        # token context window (openrouter)
    cost_per_token: float = 0.0    # prompt cost USD/token (0.0 = free)
    warmed: bool = False
    warm_latency_ms: Optional[float] = None
    provider_config: object = None  # ProviderConfig if direct provider


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


async def list_openrouter_models(tier: str = "free") -> list[ModelInfo]:
    """
    Discover OpenRouter models for the given budget tier.
    - free        : all :free models, ranked by context length
    - standard    : free models + _STANDARD_MODELS
    - performance : free models + _STANDARD_MODELS + _PERFORMANCE_MODELS
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

        catalog = {m["id"]: m for m in all_models}

        # Non-chat model families to exclude — audio, image, video, embedding, reranker
        _EXCLUDE_KEYWORDS = (
            "lyria", "imagen", "dall-e", "whisper", "tts", "embed",
            "rerank", "clip", "stable-diffusion", "midjourney", "sora",
            "audio", "speech", "music", "vision-only",
        )

        def _is_chat_model(m: dict) -> bool:
            mid = m["id"].lower()
            # OpenRouter marks modalities; if present, must include 'text' output
            arch = m.get("architecture") or {}
            modalities = arch.get("output_modalities") or arch.get("modalities") or []
            if modalities and "text" not in modalities:
                return False
            return not any(kw in mid for kw in _EXCLUDE_KEYWORDS)

        if env_override:
            wanted = {m.strip() for m in env_override.split(",") if m.strip()}
            free_pool = [m for m in all_models if m["id"] in wanted and _is_chat_model(m)]
            paid_ids: list[str] = []
        else:
            # Free pool: :free tag or zero prompt cost, chat models only
            free_pool = [
                m for m in all_models
                if _is_chat_model(m) and (
                    ":free" in m["id"]
                    or float((m.get("pricing") or {}).get("prompt", "1") or "1") == 0.0
                )
            ]
            free_pool.sort(key=lambda m: int(m.get("context_length") or 0), reverse=True)
            free_pool = free_pool[:OPENROUTER_MAX_MODELS]

            # Paid additions based on tier
            paid_ids = []
            if tier in ("standard", "performance"):
                paid_ids += _STANDARD_MODELS
            if tier == "performance":
                paid_ids += _PERFORMANCE_MODELS

        paid_pool = [catalog[mid] for mid in paid_ids if mid in catalog]
        combined = free_pool + paid_pool

        models = []
        for m in combined:
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
    local_models = []
    if USE_LOCAL_MODELS:
        all_local = await list_local_models()
        allowlist = get_race_allowlist()
        if allowlist:
            available_names = {m.name for m in all_local}
            local_models = [m for m in all_local if m.name in allowlist]
            missing = [n for n in allowlist if n not in available_names]
            if missing and verbose:
                print(f"[config] Skipping (not pulled): {missing}")
        else:
            local_models = all_local
        if verbose and local_models:
            print(f"[config] Local models: {[m.name for m in local_models]}")
    else:
        if verbose:
            print("[config] Local models: disabled (cloud available — use AGENT_LOCAL=1 to force on)")

    if not local_models and not OPENROUTER_API_KEY:
        raise RuntimeError("No Ollama models found and no OPENROUTER_API_KEY set.")

    # --- Direct provider models (OpenAI, Anthropic, Google, xAI, Mistral) ---
    from providers import models_for_tier, active_providers
    direct_models = []
    active = active_providers()
    if active:
        if verbose:
            names = [p.name for p in active]
            print(f"[config] Direct provider keys detected: {names}")
        for prov, model_id in models_for_tier(BUDGET_TIER):
            direct_models.append(ModelInfo(
                name=model_id,
                size_gb=0.0,
                provider=prov.name,
                warmed=True,
                warm_latency_ms=0.0,
                provider_config=prov,
            ))
        if verbose and direct_models:
            print(f"[config] Direct models added: {[m.name for m in direct_models]}")

    # --- OpenRouter cloud models ---
    or_models = []
    if OPENROUTER_API_KEY:
        if verbose:
            tier_label = BUDGET_TIER
            print(f"[config] OPENROUTER_API_KEY detected — fetching models (budget={tier_label})...")
        or_models = await list_openrouter_models(tier=BUDGET_TIER)
        if verbose and or_models:
            free_count = sum(1 for m in or_models if m.cost_per_token == 0.0)
            paid_count = len(or_models) - free_count
            print(f"[config] OpenRouter: {free_count} free, {paid_count} paid models ready")
    else:
        if verbose:
            print("[config] No OPENROUTER_API_KEY — skipping cloud models (set it to add free cloud racing)")

    all_models = local_models + direct_models + or_models
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
