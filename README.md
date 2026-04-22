# Speculative Agent — Cross-Vendor Parallel CoT Machine Controller

Multiple AI models from competing providers race in parallel on every task using
chain-of-thought reasoning. A supervisor short-circuits the race the moment any
model reaches high confidence. The winning action is compliance-checked against
a full regulatory lattice before execution.

**No other system does this.** OpenAI, Anthropic, Google, and xAI each run their
models in isolation. This agent races them all simultaneously — the best answer
wins regardless of vendor.

---

## Quickstart

```bash
./run.sh                          # sets up venv, installs deps, starts agent
./run.sh --budget performance     # unlock paid models (requires API keys)
./run.sh --autonomy full          # fully autonomous, no approval prompts
```

---

## Model providers

The agent discovers and races models from every configured source simultaneously.
Set any combination of keys — each one adds that provider directly to the race pool
with no routing overhead.

| Source | Env var | Models | Cost |
|--------|---------|--------|------|
| **Local** (Ollama) | *(auto-detected)* | Any pulled model | Free |
| **OpenRouter** | `OPENROUTER_API_KEY` | All `:free` models, auto-ranked by context | Free |
| **OpenAI** | `OPENAI_API_KEY` | gpt-4o-mini, gpt-4o, o3-mini | Pay-per-token |
| **Anthropic** | `ANTHROPIC_API_KEY` | claude-haiku-3.5, claude-sonnet-4 | Pay-per-token |
| **Google** | `GOOGLE_API_KEY` | gemini-2.0-flash, gemini-2.5-pro | Pay-per-token |
| **xAI** | `XAI_API_KEY` | grok-3-mini, grok-3 | Pay-per-token |
| **Mistral** | `MISTRAL_API_KEY` | mistral-small, mistral-large | Pay-per-token |

Local models are **disabled by default** when cloud keys are present — cloud models
are faster and stronger for most tasks. Use `--local` or `AGENT_LOCAL=1` to force
them into the race.

---

## Budget tiers

Controls which paid models enter the race. The agent also auto-classifies each task
and upgrades within your ceiling (e.g. vision/speed keywords trigger `performance`).

```bash
./run.sh                          # free: OpenRouter :free models only
./run.sh --budget standard        # + gpt-4o-mini, claude-haiku, gemini-flash
./run.sh --budget performance     # + gpt-4o, claude-sonnet-4, gemini-2.5-pro, grok-3
```

Also via env var: `AGENT_BUDGET=performance ./run.sh`

---

## Autonomy

```bash
./run.sh                          # normal: auto-run safe actions, ask for destructive ones
./run.sh --autonomy full          # never ask — fully autonomous
./run.sh --autonomy off           # approve every action (original behaviour)
```

**Destructive patterns that always prompt** (in `normal` mode):
`rm`, `sudo`, `dd of=`, `mkfs`, `curl|sh`, SQL `DROP`/`DELETE`, writes to `/etc/` `/usr/` `/bin/`

---

## Compliance lattice

Every action passes through a **tropical compliance lattice** before execution.
The system computes a Lagrangian `L = Σ λᵢ · cᵢ(action)` across all applicable
regulations. `L = 0` → permitted. `L > 0` → blocked with per-regulation justification.

Regulations checked: **SOC I/II/III, GDPR, CCPA, HIPAA, GLBA, FCRA, Metro II, CDIA, ISO 27001**

```
════════════════════════════════════════════════════════════
  🚫 COMPLIANCE DECISION — BASH
  Lagrangian L = 2.50  (FAIL)
────────────────────────────────────────────────────────────
  ✓ [SOC-II        ] Recorded in immutable audit log
  ✗ [GDPR          ] Art.5(1)(e): retention period not elapsed (45 of 730 days)
  ✗ [HIPAA         ] PHI must be retained 6 years. Record is 45 days old
  ◑ [ISO-27001     ] Secure disposal required. Document method.
  BLOCKED BY: GDPR, HIPAA
════════════════════════════════════════════════════════════
```

All decisions are written to an **append-only chained audit log** at
`~/.agent_audit.jsonl`. Each entry SHA-256 hashes the previous line for
SOC II tamper evidence.

---

## Privacy routing

Tasks containing sensitive keywords (`password`, `ssh`, `medical`, `bank`, etc.)
are automatically routed to **local models only** — data never leaves the machine.
Cloud models are used for everything else.

---

## How the race works

1. **Screenshot** — agent captures screen state and injects dimensions + base64 image into every model's prompt
2. **Race** — all models stream simultaneously, color-coded by provider in the terminal
3. **Short-circuit** — supervisor scores streams every 150ms; first model to hit ≥85% confidence with a valid action block wins, others are cancelled
4. **Compliance check** — Lagrangian evaluated; blocked if any regulation fires
5. **Autonomy gate** — destructive patterns prompt for approval; safe actions run immediately
6. **Execute** — action runs; result + any error fed back into next race step
7. **Pipeline** — loops until model returns `noop` (task complete) or step limit reached

---

## Action types

| Type | What it does |
|------|-------------|
| `bash` | Shell command via subprocess |
| `python_exec` | Code written to temp file, run in child process |
| `pyautogui` | Mouse/keyboard control with live screen coordinates |
| `playwright` | Full browser automation (navigate, click, fill, scrape) |
| `write_file` | Write content to a path |
| `read_file` | Read a file into model context |
| `noop` | Task complete — stops the pipeline |

---

## REPL commands

```
/models    — show all active models with provider, tier, context length
/history   — session history with per-step cost tracking
/thoughts  — full raw reasoning from every model in the last race
/quit      — exit
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENROUTER_API_KEY` | — | Enables free + paid cloud models via OpenRouter |
| `OPENAI_API_KEY` | — | Direct OpenAI (no routing overhead) |
| `ANTHROPIC_API_KEY` | — | Direct Anthropic |
| `GOOGLE_API_KEY` | — | Direct Google Gemini |
| `XAI_API_KEY` | — | Direct xAI Grok |
| `MISTRAL_API_KEY` | — | Direct Mistral |
| `AGENT_BUDGET` | `free` | `free` / `standard` / `performance` |
| `AGENT_AUTONOMY` | `normal` | `off` / `normal` / `full` |
| `AGENT_LOCAL` | `0` | `1` to force local models into race alongside cloud |
| `AGENT_MODELS` | *(allowlist)* | Comma-separated Ollama model names to include |
| `OPENROUTER_MAX_MODELS` | `5` | Max free OpenRouter models in race |
| `AGENT_AUDIT_LOG` | `~/.agent_audit.jsonl` | Compliance audit log path |
| `OLLAMA_HOST` | `http://localhost:11434` | Remote Ollama instance |

---

## Tuning

`supervisor.py`:
- `SHORT_CIRCUIT_THRESHOLD` (default `0.85`) — confidence needed to win the race
- `MIN_TOKENS_FOR_SHORTCIRCUIT` (default `40`) — minimum reasoning tokens before a win counts

`compliance.py`:
- Add constraint functions to `_CONSTRAINTS` list to extend the regulatory lattice
- Add patterns to `_DESTRUCTIVE_PATTERNS` in `executor.py` for custom safety rules
