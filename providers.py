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
"""

import os
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
            "standard":    ["claude-haiku-3-5-20241022"],
            "performance": ["claude-sonnet-4-20250514"],
        },
        auth_header="x-api-key",
        auth_prefix="",
        extra_headers={"anthropic-version": "2023-06-01"},
    ),
    ProviderConfig(
        name="google",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        api_key=os.environ.get("GOOGLE_API_KEY", ""),
        models={
            "standard":    ["gemini-2.0-flash"],
            "performance": ["gemini-2.5-pro-preview-05-06"],
        },
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


def models_for_tier(tier: str) -> list[tuple[ProviderConfig, str]]:
    """
    Return (provider, model_id) pairs for all active providers at the given tier.
    Includes models from current tier and all tiers below it.
    """
    tier_order = ["free", "standard", "performance"]
    if tier not in tier_order:
        tier = "free"
    max_idx = tier_order.index(tier)

    results = []
    for provider in active_providers():
        for t_idx, t_name in enumerate(tier_order[1:], 1):  # skip 'free'
            if t_idx <= max_idx:
                for model_id in provider.models.get(t_name, []):
                    results.append((provider, model_id))
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
