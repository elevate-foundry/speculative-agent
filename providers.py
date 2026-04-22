"""
providers.py — Direct API provider registry.

Each provider that has an API key set contributes its best models directly
to the race pool, bypassing OpenRouter entirely (no routing overhead, no
rate-limit sharing, day-one model access).

Supported providers (set the env var to activate):
  OPENAI_API_KEY       → openai
  ANTHROPIC_API_KEY    → anthropic  (uses OpenAI-compat via their v1 endpoint)
  GOOGLE_API_KEY       → google     (Gemini via OpenAI-compat endpoint)
  XAI_API_KEY          → xai        (Grok)
  MISTRAL_API_KEY      → mistral

Adding a new provider: add an entry to PROVIDER_REGISTRY below.
Model lists are auto-discovered at startup via each provider's /models endpoint.
The static lists below are fallbacks used only when discovery fails.
"""

import os
import httpx
import asyncio
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProviderConfig:
    name: str
    base_url: str
    api_key: str
    models: dict[str, list[str]]   # tier -> model IDs (cheapest/fastest first)
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer"
    extra_headers: dict[str, str] = field(default_factory=dict)
    use_messages_api: bool = False  # True = Anthropic native /v1/messages SSE format
    skip_discovery: bool = False    # True = use static model list, skip /models endpoint


PROVIDER_REGISTRY: list[ProviderConfig] = [
    ProviderConfig(
        name="openai",
        base_url="https://api.openai.com/v1",
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        models={
            "standard":    ["gpt-4o-mini"],
            "performance": ["gpt-4o", "o3-mini"],
        },
    ),
    ProviderConfig(
        name="anthropic",
        base_url="https://api.anthropic.com/v1",
        api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        models={
            "standard":    ["claude-haiku-4-5-20251001"],
            "performance": ["claude-opus-4-7", "claude-sonnet-4-6"],
        },
        auth_header="x-api-key",
        auth_prefix="",
        extra_headers={"anthropic-version": "2023-06-01"},
        use_messages_api=True,
    ),
    ProviderConfig(
        name="google",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        api_key=os.environ.get("GOOGLE_API_KEY", ""),
        models={
            "standard":    ["gemini-2.0-flash"],
            "performance": ["gemini-2.5-pro-preview-05-06"],
        },
        skip_discovery=True,  # dynamic discovery pulls gemini-2.5-flash which rate-limits
    ),
    ProviderConfig(
        name="xai",
        base_url="https://api.x.ai/v1",
        api_key=os.environ.get("XAI_API_KEY", ""),
        models={
            "standard":    ["grok-3-mini"],
            "performance": ["grok-3"],
        },
    ),
    ProviderConfig(
        name="mistral",
        base_url="https://api.mistral.ai/v1",
        api_key=os.environ.get("MISTRAL_API_KEY", ""),
        models={
            "standard":    ["mistral-small-latest"],
            "performance": ["mistral-large-latest"],
        },
    ),
]


def active_providers() -> list[ProviderConfig]:
    """Return only providers that have an API key configured."""
    return [p for p in PROVIDER_REGISTRY if p.api_key]


# Keywords that suggest a model is standard vs performance tier
_PERFORMANCE_HINTS = ("large", "pro", "plus", "max", "ultra", "heavy",
                      "sonnet", "opus", "gpt-4o", "o1", "o3",
                      "gemini-2.5", "grok-3", "mistral-large", "premier")
_STANDARD_HINTS    = ("mini", "haiku", "flash", "small", "nano", "micro",
                      "3-mini", "lite", "fast")


def _classify_model_tier(model_id: str) -> str:
    mid = model_id.lower()
    if any(h in mid for h in _PERFORMANCE_HINTS):
        return "performance"
    if any(h in mid for h in _STANDARD_HINTS):
        return "standard"
    return "standard"  # default to standard if unclear


async def discover_provider_models(provider: ProviderConfig, verbose: bool = False) -> None:
    """
    Query the provider's /models endpoint and update provider.models in place.
    Falls back to the static list if the API call fails.
    Filters to chat/text-generation models only.
    """
    if not provider.api_key or provider.skip_discovery:
        return

    headers = {provider.auth_header: f"{provider.auth_prefix} {provider.api_key}".strip()}
    headers.update(provider.extra_headers)

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{provider.base_url}/models", headers=headers)
            resp.raise_for_status()
            data = resp.json()

        # Normalise: OpenAI/Mistral/xAI return {"data": [...]}
        # Anthropic returns {"models": [...]} but we skip it above
        # Google returns {"models": [...]} with name like "models/gemini-2.0-flash"
        raw = data.get("data") or data.get("models") or []

        chat_models: list[str] = []
        for m in raw:
            mid = m.get("id") or m.get("name", "")
            # Google prefixes with "models/" — strip it
            if mid.startswith("models/"):
                mid = mid[len("models/"):]
            if not mid:
                continue
            # Filter to generative text models only
            skip_keywords = ("embedding", "embed", "tts", "whisper", "dall-e",
                             "image", "vision-only", "moderation", "instruct-v")
            if any(k in mid.lower() for k in skip_keywords):
                continue
            # Google-specific: skip non-generative model types
            supported = m.get("supportedGenerationMethods") or []
            if supported and "generateContent" not in supported and "streamGenerateContent" not in supported:
                continue
            chat_models.append(mid)

        if not chat_models:
            return  # discovery returned nothing useful, keep fallback

        # Bucket into tiers
        standard: list[str] = []
        performance: list[str] = []
        for mid in chat_models:
            if _classify_model_tier(mid) == "performance":
                performance.append(mid)
            else:
                standard.append(mid)

        provider.models = {
            "standard": standard,
            "performance": performance,
        }

        if verbose:
            print(f"[providers] {provider.name}: discovered {len(standard)} standard, "
                  f"{len(performance)} performance models")

    except Exception as e:
        if verbose:
            print(f"[providers] {provider.name}: model discovery failed ({e}), using fallback list")


async def discover_all_provider_models(verbose: bool = False) -> None:
    """Run model discovery for all active providers in parallel."""
    await asyncio.gather(*[
        discover_provider_models(p, verbose=verbose)
        for p in active_providers()
    ])


def models_for_tier(tier: str) -> list[tuple[ProviderConfig, str]]:
    """
    Return (provider, model_id) pairs for all active providers at the given tier.
    Includes models from current tier and all tiers below it.
    """
    tier_order = ["free", "standard", "performance"]
    if tier not in tier_order:
        tier = "free"
    max_idx = tier_order.index(tier)

    MAX_PER_PROVIDER = 2  # avoid hammering rate limits with 9 Claude models simultaneously

    results = []
    for provider in active_providers():
        added = 0
        # Prefer highest tier first, then fall down
        for t_name in reversed(tier_order[1:max_idx + 1]):
            for model_id in provider.models.get(t_name, []):
                if added >= MAX_PER_PROVIDER:
                    break
                results.append((provider, model_id))
                added += 1
            if added >= MAX_PER_PROVIDER:
                break
    return results


def register_key(provider_name: str, api_key: str) -> bool:
    """
    Register a new API key for a provider at runtime.
    Called by the agent when it acquires a key (e.g. via Playwright signup).
    Returns True if the provider was found and updated.
    """
    for p in PROVIDER_REGISTRY:
        if p.name == provider_name.lower():
            p.api_key = api_key
            os.environ[f"{provider_name.upper()}_API_KEY"] = api_key
            return True
    return False
