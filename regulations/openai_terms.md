# OpenAI Usage Policies & Terms of Service

**Source:** https://openai.com/policies/usage-policies (effective March 2024)  
**Applicability:** All API access to GPT-4o, GPT-4, o3, and related models

---

## Key Operative Provisions

### Section 3 — Usage Policies

> **3.1 Prohibited Uses.** You may not use the API to:
> (a) develop or train competing AI models without written consent;
> (b) use output to create content that violates applicable law;
> (c) use the API in a manner that poses safety risks to individuals or groups;
> (d) circumvent safety measures or content filters.

### Section 4 — Data and Privacy

> **4.1 Data Processing.** OpenAI processes prompts and completions as described in
> the API Data Privacy documentation. By default, API inputs and outputs are not
> used to train OpenAI models (as of March 2023).

> **4.2 Data Retention.** OpenAI retains API inputs and outputs for up to 30 days
> for abuse monitoring, then deletes them unless legally required to retain.

### Section 5 — Enterprise Data Controls

> **5.1 Zero Data Retention (ZDR).** Enterprise customers may request ZDR whereby
> no request or response data is stored beyond the immediate request lifecycle.

> **5.2 SOC 2 Type II.** OpenAI maintains SOC 2 Type II certification covering
> Security, Availability, and Confidentiality trust service criteria. Reports
> available under NDA to enterprise customers.

### Section 7 — Autonomous Agents

> **7.1 Human Oversight.** When using the API to build autonomous or semi-autonomous
> agents, developers must implement appropriate human oversight mechanisms and must
> not deploy agents that take irreversible actions without user confirmation.

> **7.2 Action Logging.** Autonomous agent deployments must maintain logs of
> consequential actions for audit purposes.

---

## Compliance Lattice Mapping

| Provision | Lattice Constraint | Weight |
|-----------|-------------------|--------|
| §3.1 Prohibited Uses | `Block` if task involves prohibited content | λ=2 |
| §4.2 Data Retention | `Conditional` for PII in prompt | λ=1 |
| §7.1 Human Oversight | Autonomy level must match task risk | λ=2 |
| §7.2 Action Logging | All actions must be audit-logged | λ=2 |
| §5.2 SOC 2 Type II | Log integrity via hash chain required | λ=1 |

---

## Autonomous Agent Constraints (Speculative Agent)

The Speculative Agent system respects OpenAI's §7.1 requirement through:
1. **Preflight risk assessment** — models vote on required autonomy before execution
2. **Configurable autonomy ceiling** — user-set maximum autonomy level
3. **Critical risk halt** — irreversible actions always require confirmation
4. **SOC 2 audit log** — every action recorded with SHA-256 hash chain
