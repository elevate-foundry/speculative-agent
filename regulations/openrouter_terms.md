# OpenRouter Terms of Service & Model Provider Pass-Through Policies

**Source:** https://openrouter.ai/terms (effective 2024)  
**Applicability:** All models accessed via api.openrouter.ai

---

## Key Operative Provisions

### Section 2 — Nature of Service

> **2.1 Router Role.** OpenRouter acts as an API aggregator and router, not as
> the underlying model provider. By using OpenRouter, you agree to comply with
> the terms of service of each underlying model provider (OpenAI, Anthropic,
> Google, Meta, Mistral, etc.) as if you were accessing those models directly.

> **2.2 Pass-Through Compliance.** Your obligations under upstream provider
> acceptable use policies pass through to you. OpenRouter does not absolve
> users of obligations imposed by underlying providers.

### Section 3 — Prohibited Uses

> **3.1 General Prohibitions.** You may not use OpenRouter to:
> (a) circumvent rate limits or usage quotas of underlying providers;
> (b) resell API access without written authorization;
> (c) use models for purposes prohibited by their respective providers;
> (d) attempt to identify or reverse-engineer model weights.

### Section 5 — Data Handling

> **5.1 Prompt Logging.** OpenRouter may log prompts and completions for
> abuse detection. Logs are retained for 30 days. Enterprise plans offer
> prompt logging opt-out.

> **5.2 Model Routing Data.** Metadata about routing decisions (model selected,
> latency, token counts) is retained to improve the service.

### Section 6 — Availability & SLA

> **6.1 Best-Effort Routing.** OpenRouter routes to the best available provider
> instance but does not guarantee availability of any specific model. Rate limits
> are enforced per model per API key.

> **6.2 Fallback Behavior.** When a model is unavailable, OpenRouter may
> silently route to an alternative provider variant unless opt-out is specified
> via the `route: "fallback": false` parameter.

---

## Pass-Through Compliance Requirements

Since OpenRouter provides access to models from multiple providers, the
Speculative Agent must comply with **all** of the following simultaneously:

| Provider | Key Terms File | Critical Constraint |
|----------|---------------|---------------------|
| OpenAI | `openai_terms.md` | §7.1 Human Oversight |
| Anthropic | `anthropic_terms.md` | §6.2 Minimal Footprint |
| Google | `google_terms.md` | §7.2 Human Review |
| Meta (Llama) | Meta Llama Use Policy | Non-commercial restrictions on some tiers |
| Mistral | Mistral AI ToS | GDPR data processing obligations |

## Compliance Lattice Mapping

| Provision | Lattice Constraint | Weight |
|-----------|-------------------|--------|
| §2.1 Pass-Through | All upstream constraints apply | λ=2 |
| §3.1(a) Rate Limits | Agent must respect 429 backoff | λ=1 |
| §5.1 Prompt Logging | PII must not appear in prompts | λ=2 |
| §6.2 Fallback | Model identity must be logged | λ=1 |

---

## Multi-Provider Race Compliance

The Speculative Agent's parallel racing architecture creates a unique
compliance challenge: a single user prompt is simultaneously sent to models
from OpenAI, Anthropic, Google, and OpenRouter. The compliance system must
satisfy the **intersection** of all provider policies, not just one.

The compliance Lagrangian handles this via the join operation:
```
L(a, d) = max_i(λ_i · v_i(a, d))  over ALL providers' constraints
```
A single Block verdict from any provider's constraint function blocks execution.
