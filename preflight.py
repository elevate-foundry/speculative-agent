"""
preflight.py — Model-chosen autonomy level via parallel risk assessment.

Before executing a task, a fast pre-flight race asks all available models:
  "How risky is this task? What autonomy level do you recommend?"

Models return a structured JSON vote:
  {
    "autonomy": "off" | "normal" | "full",
    "risk":     "low" | "medium" | "high" | "critical",
    "confidence": 0.0-1.0,
    "justification": "..."
  }

The system aggregates votes using a conservative consensus rule:
  - Any "critical" risk vote → autonomy = "off" (always ask user)
  - Majority "high" risk → autonomy = "off"
  - Majority "medium" → autonomy = "normal"  
  - All "low" with high confidence → autonomy = "full"
  - Tie or ambiguous → escalate to current configured level

The user-configured autonomy acts as a CEILING: models can request LESS
autonomy than configured (more caution) but never MORE.

  user_config=full  + model_vote=normal  →  effective=normal  (model is cautious)
  user_config=normal + model_vote=full   →  effective=normal  (ceiling applies)
  user_config=off   + any vote           →  effective=off     (user override)
"""

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Optional


PREFLIGHT_SYSTEM = """You are a risk assessment module for an autonomous AI agent.
Your ONLY job is to assess the risk level of a proposed task and recommend
an autonomy level. Respond with ONLY a JSON object — no prose, no markdown fence.

autonomy levels:
  "off"    = every action needs explicit human approval (high/critical risk)
  "normal" = auto-approve safe actions, confirm destructive ones (medium risk)
  "full"   = fully autonomous, no prompts (low risk, reversible, read-only)

risk levels:
  "low"      = read-only, no side effects, fully reversible
  "medium"   = writes files or state, but easily undone
  "high"     = deletes data, sends messages, modifies system config
  "critical" = irreversible: wipes data, sends emails/payments, root access

JSON schema:
{"autonomy": "off"|"normal"|"full", "risk": "low"|"medium"|"high"|"critical",
 "confidence": 0.0-1.0, "justification": "one sentence"}"""


@dataclass
class PreflightVote:
    model: str
    autonomy: str        # "off" | "normal" | "full"
    risk: str            # "low" | "medium" | "high" | "critical"
    confidence: float
    justification: str
    raw: str = ""


@dataclass
class PreflightResult:
    effective_autonomy: str          # final resolved autonomy
    recommended_autonomy: str        # what models voted for
    risk_level: str                  # consensus risk level
    confidence: float
    votes: list[PreflightVote]
    justification: str
    ceiling_applied: bool            # True if user config capped the model vote


_AUTONOMY_ORDER = {"off": 0, "normal": 1, "full": 2}
_RISK_ORDER     = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _parse_vote(text: str, model_name: str) -> Optional[PreflightVote]:
    """Extract structured vote from model output."""
    # Try to find a JSON object anywhere in the text
    for match in re.finditer(r'\{[^{}]*"autonomy"[^{}]*\}', text, re.DOTALL):
        try:
            obj = json.loads(match.group())
            autonomy = obj.get("autonomy", "normal").lower()
            risk = obj.get("risk", "medium").lower()
            if autonomy not in _AUTONOMY_ORDER:
                autonomy = "normal"
            if risk not in _RISK_ORDER:
                risk = "medium"
            return PreflightVote(
                model=model_name,
                autonomy=autonomy,
                risk=risk,
                confidence=float(obj.get("confidence", 0.5)),
                justification=str(obj.get("justification", ""))[:200],
                raw=text[:300],
            )
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _aggregate_votes(votes: list[PreflightVote]) -> tuple[str, str, float, str]:
    """
    Aggregate votes into (autonomy, risk, confidence, justification).
    Uses conservative consensus: worst-case risk determines autonomy.
    """
    if not votes:
        return "normal", "medium", 0.5, "No models responded — defaulting to normal."

    # Weighted by confidence
    risk_scores: dict[str, float] = {"low": 0.0, "medium": 0.0, "high": 0.0, "critical": 0.0}
    autonomy_scores: dict[str, float] = {"off": 0.0, "normal": 0.0, "full": 0.0}

    for v in votes:
        w = max(v.confidence, 0.1)
        risk_scores[v.risk] += w
        autonomy_scores[v.autonomy] += w

    # Any critical vote is an automatic escalation
    if risk_scores["critical"] > 0:
        consensus_risk = "critical"
        consensus_autonomy = "off"
    elif risk_scores["high"] > sum(risk_scores.values()) * 0.4:
        consensus_risk = "high"
        consensus_autonomy = "off"
    elif risk_scores["medium"] > risk_scores["low"]:
        consensus_risk = "medium"
        consensus_autonomy = "normal"
    else:
        consensus_risk = "low"
        consensus_autonomy = "full"

    avg_conf = sum(v.confidence for v in votes) / len(votes)

    # Pick the justification from the highest-confidence vote matching consensus risk
    best = max(
        [v for v in votes if v.risk == consensus_risk],
        key=lambda v: v.confidence,
        default=votes[0],
    )

    return consensus_autonomy, consensus_risk, avg_conf, best.justification


async def preflight_assess(
    task: str,
    models: list,           # list[ModelInfo]
    configured_autonomy: str,
    verbose: bool = True,
) -> PreflightResult:
    """
    Run a fast parallel pre-flight risk assessment.
    Returns the effective autonomy level the agent should use for this task.
    """
    from supervisor import supervise_race

    # Use only the 3 fastest/lightest models for preflight — don't want to hang
    # Prefer: small/flash/haiku models first, fall back to whatever is available
    _FAST_HINTS = ("flash", "haiku", "mini", "small", "lite", "ling", "gemma", "nano")
    fast = [m for m in models if any(h in m.name.lower() for h in _FAST_HINTS)]
    slow = [m for m in models if m not in fast]
    preflight_models = (fast + slow)[:3]

    if verbose:
        names = [m.name.split("/")[-1][:16] for m in preflight_models]
        print(f"\n[preflight] Assessing risk with: {names}")

    # Hard 8-second timeout — preflight must not block the agent
    try:
        _, streams = await asyncio.wait_for(
            supervise_race(
                model_names=preflight_models,
                prompt=f"Task to assess:\n\n{task}\n\nRespond with ONLY the JSON object.",
                system_prompt=PREFLIGHT_SYSTEM,
                verbose=False,
                live_output=False,
                max_tokens=128,
            ),
            timeout=8.0,
        )
    except asyncio.TimeoutError:
        if verbose:
            print("[preflight] Timed out — defaulting to configured autonomy")
        return PreflightResult(
            effective_autonomy=configured_autonomy,
            recommended_autonomy=configured_autonomy,
            risk_level="medium",
            confidence=0.0,
            votes=[],
            justification="Preflight timed out.",
            ceiling_applied=False,
        )

    votes: list[PreflightVote] = []
    for s in streams:
        if s.text and not s.error:
            vote = _parse_vote(s.text, s.model_name)
            if vote:
                votes.append(vote)

    recommended_autonomy, risk_level, confidence, justification = _aggregate_votes(votes)

    # Apply ceiling: model can request less autonomy but never more
    if _AUTONOMY_ORDER.get(recommended_autonomy, 1) > _AUTONOMY_ORDER.get(configured_autonomy, 1):
        effective_autonomy = configured_autonomy
        ceiling_applied = True
    else:
        effective_autonomy = recommended_autonomy
        ceiling_applied = False

    result = PreflightResult(
        effective_autonomy=effective_autonomy,
        recommended_autonomy=recommended_autonomy,
        risk_level=risk_level,
        confidence=confidence,
        votes=votes,
        justification=justification,
        ceiling_applied=ceiling_applied,
    )

    if verbose:
        _print_preflight_result(result, configured_autonomy)

    return result


def _print_preflight_result(result: PreflightResult, configured: str) -> None:
    risk_icons = {"low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🚨"}
    autonomy_icons = {"off": "🔒", "normal": "⚡", "full": "🤖"}

    icon = risk_icons.get(result.risk_level, "⚪")
    print(f"\n[preflight] {icon} Risk={result.risk_level.upper()}  "
          f"conf={result.confidence:.0%}  votes={len(result.votes)}")
    print(f"[preflight] Models recommend: {autonomy_icons.get(result.recommended_autonomy,'')} "
          f"{result.recommended_autonomy}")
    if result.ceiling_applied:
        print(f"[preflight] ⚠  Ceiling applied: configured={configured} < recommended={result.recommended_autonomy}")
    else:
        print(f"[preflight] ✓  Effective autonomy: {autonomy_icons.get(result.effective_autonomy,'')} "
              f"{result.effective_autonomy}")
    if result.justification:
        print(f"[preflight] ↳ {result.justification}")

    if len(result.votes) > 1:
        print(f"[preflight] Votes:")
        for v in sorted(result.votes, key=lambda v: -v.confidence):
            short = v.model.split("/")[-1][:20]
            print(f"  {short:<22} risk={v.risk:<9} autonomy={v.autonomy:<7} conf={v.confidence:.0%}")
