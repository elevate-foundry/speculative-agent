# Anthropic Usage Policy & API Terms

**Source:** https://www.anthropic.com/legal/aup (effective January 2025)  
**Applicability:** All API access to Claude Opus, Sonnet, Haiku models

---

## Key Operative Provisions

### Acceptable Use Policy — Prohibited Categories

> **Automated Decision-Making.** You may not use Claude to make consequential
> automated decisions affecting individuals' legal rights, financial standing,
> employment, health, or safety without appropriate human oversight and the
> ability for affected individuals to seek review.

> **Weapons & Critical Infrastructure.** You may not use Claude to assist in
> developing weapons of mass destruction, attacking critical infrastructure,
> or circumventing security controls.

> **Deceptive Agents.** You may not deploy Claude in agentic contexts where it
> impersonates humans or conceals its AI nature from users who would object.

### API Terms of Service — Section 6: Agentic Use

> **6.1 Operator Responsibility.** When deploying Claude in agentic or automated
> pipelines, operators bear responsibility for ensuring appropriate guardrails,
> monitoring, and intervention capabilities are in place.

> **6.2 Minimal Footprint Principle.** Agentic deployments should request only
> necessary permissions, prefer reversible over irreversible actions, and err
> on the side of doing less and confirming with users when uncertain.

> **6.3 Prompt Injection Defense.** Operators must implement defenses against
> prompt injection attacks in agentic contexts where Claude processes
> third-party content.

### Section 8 — Data Privacy

> **8.1 Training Data.** Anthropic does not use API inputs/outputs to train
> Claude models by default. Enterprise customers receive contractual guarantees.

> **8.2 Data Retention.** API data retained for up to 30 days for trust and
> safety review, then purged unless retention is legally required.

### Section 9 — Security

> **9.1 SOC 2 Type II.** Anthropic maintains SOC 2 Type II certification.
> Security assessments available to enterprise customers under NDA.

---

## Compliance Lattice Mapping

| Provision | Lattice Constraint | Weight |
|-----------|-------------------|--------|
| AUP §Automated Decisions | `Block` for consequential decisions without oversight | λ=2 |
| §6.2 Minimal Footprint | Prefer `Conditional` for irreversible actions | λ=2 |
| §6.3 Prompt Injection | `Block` if prompt contains injection patterns | λ=1 |
| §8.1 Training Data | `Permit` — no training by default | λ=0 |
| §9.1 SOC 2 | Hash-chain audit log required | λ=1 |

---

## Minimal Footprint Compliance (Speculative Agent)

The Speculative Agent system implements Anthropic's §6.2 Minimal Footprint Principle:
1. **Preflight assessment** requests minimum required autonomy level
2. **Conservative consensus** — any high-risk vote elevates caution
3. **Reversibility preference** encoded in compliance Lagrangian weights
4. **Scope limitation** — privacy-sensitive tasks routed to local models only
