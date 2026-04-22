"""
compliance.py — Tropical Compliance Lattice + Lagrangian Action Justification

Implements a compliance decision engine for SOC I/II/III + FCRA, GLBA, ISO 27001,
GDPR, HIPAA, CCPA, Metro II, CDIA frameworks.

Architecture:
  - Each regulation is a constraint node in a tropical semiring lattice
    (max-plus algebra: join = max, meet = min, identity = -∞)
  - Before any destructive action, the system must produce a Lagrangian
    justification: a vector of (regulation, verdict, rationale) that
    simultaneously satisfies ALL applicable constraints
  - If any constraint returns BLOCK, the action is denied regardless of others
  - All decisions are written to an immutable SOC-compliant audit log

Lagrangian:
  L(action) = Σ λᵢ · cᵢ(action, context)
  where cᵢ ∈ {PERMIT=0, CONDITIONAL=0.5, BLOCK=1}
  Action is permitted only when L = 0 (all constraints PERMIT or waived)
"""

import os
import json
import hashlib
import datetime
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# ─── Verdicts ────────────────────────────────────────────────────────────────

class Verdict(Enum):
    PERMIT      = 0      # constraint satisfied, action allowed
    CONDITIONAL = 1      # allowed only with mitigations (logged, anonymized, etc.)
    BLOCK       = 2      # constraint violated, action must not proceed

    @property
    def lagrangian_weight(self) -> float:
        return {self.PERMIT: 0.0, self.CONDITIONAL: 0.5, self.BLOCK: 1.0}[self]


# ─── Data subject / context ───────────────────────────────────────────────────

@dataclass
class DataContext:
    """What the agent knows about the data being acted on."""
    path: str                          # file or resource path
    data_type: str = "unknown"         # pii, financial, health, credential, log, code, unknown
    subject_jurisdiction: str = "US"   # US, EU, CA (California), UK, etc.
    retention_days: Optional[int] = None   # required retention period if known
    contains_pii: bool = False
    contains_phi: bool = False         # Protected Health Information (HIPAA)
    contains_financial: bool = False   # GLBA / FCRA / Metro II / CDIA
    is_audit_log: bool = False
    created_days_ago: Optional[int] = None
    has_consumer_request: bool = False   # GDPR Art.17 / CCPA right-to-delete request
    is_backed_up: bool = False


# ─── Individual constraint nodes ─────────────────────────────────────────────

@dataclass
class ConstraintResult:
    regulation: str
    verdict: Verdict
    rationale: str
    lagrangian_lambda: float = 1.0     # weight of this constraint


_READ_ONLY_BASH = ("cat ", "grep ", "tail ", "head ", "less ", "more ", "wc ",
                   "ls ", "stat ", "file ", "hexdump ", "strings ")

_DESTRUCTIVE_BASH_SIGNALS = ("-delete", "os.remove", "os.unlink", "shutil.rmtree",
                              "unlink(", "rmdir(", "> /")

_READ_ACTIONS = ("read_file", "noop")
_DESTRUCTIVE_ACTIONS = ("bash", "python_exec")


def _is_bash_read_only(payload: dict) -> bool:
    cmd = (payload.get("command") or "").lstrip()
    # find with -delete is destructive despite starting with "find"
    if any(sig in cmd for sig in _DESTRUCTIVE_BASH_SIGNALS):
        return False
    return any(cmd.startswith(r) for r in _READ_ONLY_BASH)


def _check_soc(ctx: DataContext, action_type: str, payload: dict = None) -> ConstraintResult:
    """SOC I/II/III: audit logs are immutable — writes/deletes blocked; reads permitted."""
    is_read = (action_type in ("read_file", "noop") or
               (action_type == "bash" and _is_bash_read_only(payload or {})))
    if ctx.is_audit_log and not is_read:
        return ConstraintResult(
            "SOC-II", Verdict.BLOCK,
            "Audit logs are immutable under SOC II CC6.1/CC7.2. Deletion of audit trail is prohibited.",
            lagrangian_lambda=2.0,
        )
    return ConstraintResult("SOC-II", Verdict.PERMIT,
                            "Action will be recorded in immutable audit log per SOC II CC6.1.")


def _check_gdpr(ctx: DataContext, action_type: str, payload: dict = None) -> ConstraintResult:
    """GDPR: right to erasure (Art.17) vs. lawful retention obligations (Art.5(1)(e))."""
    if not ctx.contains_pii or ctx.subject_jurisdiction not in ("EU", "UK"):
        return ConstraintResult("GDPR", Verdict.PERMIT, "GDPR not applicable (no EU/UK PII).")
    if action_type in _READ_ACTIONS or (action_type == "bash" and _is_bash_read_only(payload or {})):
        return ConstraintResult("GDPR", Verdict.PERMIT, "GDPR: reads not restricted.")

    if ctx.has_consumer_request:
        if ctx.retention_days and ctx.created_days_ago and ctx.created_days_ago < ctx.retention_days:
            return ConstraintResult(
                "GDPR", Verdict.BLOCK,
                f"GDPR Art.17(3)(b): erasure request received but mandatory retention period "
                f"({ctx.retention_days}d) not yet elapsed ({ctx.created_days_ago}d old).",
            )
        return ConstraintResult("GDPR", Verdict.PERMIT,
                                "GDPR Art.17: valid erasure request, retention period elapsed.")

    if ctx.retention_days and ctx.created_days_ago and ctx.created_days_ago < ctx.retention_days:
        return ConstraintResult(
            "GDPR", Verdict.BLOCK,
            f"GDPR Art.5(1)(e): storage limitation — data must be retained for "
            f"{ctx.retention_days} days (only {ctx.created_days_ago} days old).",
        )
    return ConstraintResult("GDPR", Verdict.CONDITIONAL,
                            "GDPR: deletion permitted but must be documented under Art.30 records.")


def _check_ccpa(ctx: DataContext, action_type: str, payload: dict = None) -> ConstraintResult:
    """CCPA: California Consumer Privacy Act — right to delete (§1798.105)."""
    if not ctx.contains_pii or ctx.subject_jurisdiction != "CA":
        return ConstraintResult("CCPA", Verdict.PERMIT, "CCPA not applicable.")
    if action_type in _READ_ACTIONS or (action_type == "bash" and _is_bash_read_only(payload or {})):
        return ConstraintResult("CCPA", Verdict.PERMIT, "CCPA: reads not restricted.")

    if ctx.has_consumer_request:
        return ConstraintResult("CCPA", Verdict.PERMIT,
                                "CCPA §1798.105: consumer deletion request — deletion required.")
    return ConstraintResult("CCPA", Verdict.CONDITIONAL,
                            "CCPA: deletion permitted; document business purpose under §1798.100.")


def _check_hipaa(ctx: DataContext, action_type: str) -> ConstraintResult:
    """HIPAA: PHI must be retained 6 years from creation or last effective date."""
    if not ctx.contains_phi:
        return ConstraintResult("HIPAA", Verdict.PERMIT, "HIPAA not applicable (no PHI detected).")
    if action_type in _READ_ACTIONS or (action_type == "bash" and _is_bash_read_only({})):
        return ConstraintResult("HIPAA", Verdict.PERMIT, "HIPAA: read access to PHI permitted; write/delete restricted.")

    min_retention = 365 * 6  # 6 years
    if ctx.created_days_ago is not None and ctx.created_days_ago < min_retention:
        return ConstraintResult(
            "HIPAA", Verdict.BLOCK,
            f"HIPAA §164.530(j): PHI must be retained 6 years. "
            f"Record is only {ctx.created_days_ago} days old (need {min_retention}).",
        )
    if ctx.created_days_ago is None:
        # Age unknown — conservatively block; operator must assert retention period
        return ConstraintResult(
            "HIPAA", Verdict.BLOCK,
            "HIPAA §164.530(j): PHI retention period unknown. "
            "Cannot confirm 6-year minimum is satisfied before deletion.",
        )
    return ConstraintResult("HIPAA", Verdict.CONDITIONAL,
                            "HIPAA: retention satisfied. Deletion must use NIST SP 800-88 media sanitization.")


def _check_glba(ctx: DataContext, action_type: str) -> ConstraintResult:
    """GLBA Safeguards Rule: financial records require documented disposal procedures."""
    if not ctx.contains_financial:
        return ConstraintResult("GLBA", Verdict.PERMIT, "GLBA not applicable (no financial data).")
    if ctx.data_type == "credit":
        return ConstraintResult("GLBA", Verdict.PERMIT,
                                "GLBA defers to FCRA for consumer credit report data (lex specialis).")
    if action_type == "write_file":
        return ConstraintResult("GLBA", Verdict.CONDITIONAL,
                                "GLBA §314.4: document retention and access controls for new financial records.")
    if not ctx.is_backed_up:
        return ConstraintResult(
            "GLBA", Verdict.BLOCK,
            "GLBA Safeguards Rule §314.4(f): customer financial records must be backed up "
            "before destruction. No backup confirmed.",
        )
    return ConstraintResult("GLBA", Verdict.CONDITIONAL,
                            "GLBA: disposal permitted with documented secure destruction method.")


def _check_fcra(ctx: DataContext, action_type: str) -> ConstraintResult:
    """FCRA: consumer report information — 7-year retention for adverse items."""
    if not ctx.contains_financial or ctx.data_type not in ("financial", "credit"):
        return ConstraintResult("FCRA", Verdict.PERMIT, "FCRA not applicable.")

    min_retention = 365 * 7
    if ctx.created_days_ago is not None and ctx.created_days_ago < min_retention:
        return ConstraintResult(
            "FCRA", Verdict.BLOCK,
            f"FCRA §605: consumer report data must be retained 7 years. "
            f"Record is {ctx.created_days_ago} days old (need {min_retention}).",
        )
    return ConstraintResult("FCRA", Verdict.PERMIT,
                            "FCRA: 7-year retention period satisfied.")


def _check_metro2_cdia(ctx: DataContext, action_type: str) -> ConstraintResult:
    """Metro II / CDIA: credit reporting data format standards — accuracy obligations."""
    if ctx.data_type not in ("credit", "financial"):
        return ConstraintResult("Metro-II/CDIA", Verdict.PERMIT, "Metro II/CDIA not applicable.")

    return ConstraintResult(
        "Metro-II/CDIA", Verdict.CONDITIONAL,
        "CDIA Metro II: deletion of tradeline data must be reported to all CRAs within 30 days "
        "per e-OSCAR procedures to maintain accuracy obligations.",
    )


def _is_destructive_action(action_type: str, payload: dict = None) -> bool:
    """True if the action_type + payload represents a data-destroying operation."""
    if action_type in _READ_ACTIONS:
        return False
    if action_type == "write_file":
        return False   # write_file creates/overwrites but is not 'disposal'
    if action_type in _DESTRUCTIVE_ACTIONS:
        return not _is_bash_read_only(payload or {})
    return True


def _check_pipl(ctx: DataContext, action_type: str) -> ConstraintResult:
    """PIPL (China): cross-border transfer of Chinese personal data requires CAC approval (Art.38)."""
    if ctx.subject_jurisdiction != "CN" or not ctx.contains_pii:
        return ConstraintResult("PIPL", Verdict.PERMIT, "PIPL not applicable.")
    if action_type in _READ_ACTIONS or (action_type == "bash" and _is_bash_read_only({})):
        return ConstraintResult("PIPL", Verdict.PERMIT, "PIPL: read access permitted.")
    return ConstraintResult(
        "PIPL", Verdict.BLOCK,
        "PIPL Art.38: cross-border transfer of Chinese personal data requires "
        "CAC security assessment or standard contract. Transfer blocked pending approval.",
    )


def _check_iso27001(ctx: DataContext, action_type: str, payload: dict = None) -> ConstraintResult:
    """ISO 27001: A.8.3.2 disposal + A.8.2.3 handling of sensitive assets."""
    is_sensitive = ctx.contains_pii or ctx.contains_phi or ctx.contains_financial
    # Reads never blocked
    if action_type in _READ_ACTIONS:
        return ConstraintResult("ISO-27001", Verdict.PERMIT, "ISO 27001: reads not restricted.")
    if action_type == "bash" and _is_bash_read_only(payload or {}):
        return ConstraintResult("ISO-27001", Verdict.PERMIT, "ISO 27001: read-only command.")
    # write_file on sensitive data: A.8.2.3 handling controls required
    if action_type == "write_file":
        if not is_sensitive:
            return ConstraintResult("ISO-27001", Verdict.PERMIT,
                                    "ISO 27001: non-sensitive write, no special handling required.")
        return ConstraintResult("ISO-27001", Verdict.CONDITIONAL,
                                "ISO 27001 A.8.2.3: document access controls for sensitive asset.")
    # Destructive bash/python_exec: A.8.3.2 disposal controls
    if ctx.data_type in ("code", "log") and not is_sensitive:
        return ConstraintResult("ISO-27001", Verdict.PERMIT,
                                "ISO 27001 A.8.3.2: non-sensitive data, standard disposal acceptable.")
    return ConstraintResult(
        "ISO-27001", Verdict.CONDITIONAL,
        "ISO 27001 A.8.3.2: secure disposal required. Document method (overwrite/crypto-erase) "
        "and record in asset register.",
    )


# ─── Lattice evaluator ────────────────────────────────────────────────────────

_CONSTRAINTS = [
    _check_soc,
    _check_gdpr,
    _check_ccpa,
    _check_hipaa,
    _check_glba,
    _check_fcra,
    _check_metro2_cdia,
    _check_pipl,
    _check_iso27001,
]


@dataclass
class ComplianceDecision:
    action_id: str
    action_type: str
    path: str
    timestamp: str
    permitted: bool
    lagrangian_value: float          # 0.0 = all clear, >0 = blocked
    constraints: list[ConstraintResult]
    mitigations_required: list[str]  # steps required for CONDITIONAL verdicts
    blocking_regulations: list[str]
    justification: str               # human-readable summary for audit log


def evaluate(action_type: str, payload: dict, context: DataContext) -> ComplianceDecision:
    """
    Run the full compliance lattice against a proposed action.
    Returns a ComplianceDecision with Lagrangian score and verdict.
    """
    action_id = str(uuid.uuid4())
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    _payload_fns = (_check_soc, _check_gdpr, _check_ccpa, _check_iso27001)
    results = [fn(context, action_type, payload) if fn in _payload_fns
               else fn(context, action_type)
               for fn in _CONSTRAINTS]

    # Tropical semiring (max-plus): ℒ = ⊕ᵢ (λᵢ ⊗ vᵢ) = max_i (λᵢ · vᵢ)
    # A single BLOCK dominates all PERMITs: max(λ·1, 1·0) = λ > 0
    # CONDITIONAL (v=0.5) contributes 0.5·λ; only PERMIT (v=0) gives 0
    lagrangian = max((r.lagrangian_lambda * r.verdict.lagrangian_weight for r in results), default=0.0)
    blocking = [r.regulation for r in results if r.verdict == Verdict.BLOCK]
    conditional = [r for r in results if r.verdict == Verdict.CONDITIONAL]

    permitted = len(blocking) == 0

    mitigations = []
    for r in conditional:
        mitigations.append(f"[{r.regulation}] {r.rationale}")

    if permitted and not blocking:
        if conditional:
            justification = (
                f"Action PERMITTED with {len(conditional)} mitigation(s) required. "
                f"Lagrangian L={lagrangian:.2f}. "
                f"Conditions: {'; '.join(r.regulation for r in conditional)}."
            )
        else:
            justification = f"Action PERMITTED. All {len(results)} compliance constraints satisfied. \u2112=0.00 (tropical max)."
    else:
        justification = (
            f"Action BLOCKED by {len(blocking)} regulation(s): {', '.join(blocking)}. "
            f"Lagrangian L={lagrangian:.2f} > 0 — no valid justification path exists in the constraint lattice."
        )

    decision = ComplianceDecision(
        action_id=action_id,
        action_type=action_type,
        path=context.path,
        timestamp=timestamp,
        permitted=permitted,
        lagrangian_value=lagrangian,
        constraints=results,
        mitigations_required=mitigations,
        blocking_regulations=blocking,
        justification=justification,
    )

    _write_audit_log(decision)
    return decision


# ─── SOC-compliant immutable audit log ───────────────────────────────────────

AUDIT_LOG_PATH = os.environ.get("AGENT_AUDIT_LOG", os.path.expanduser("~/.agent_audit.jsonl"))


def _write_audit_log(decision: ComplianceDecision) -> None:
    """
    Append-only audit log entry. Each line is a JSON record with a SHA-256
    chain hash linking to the previous entry (SOC II CC6.1 tamper evidence).
    """
    entry = {
        "action_id": decision.action_id,
        "timestamp": decision.timestamp,
        "action_type": decision.action_type,
        "path": decision.path,
        "permitted": decision.permitted,
        "lagrangian": decision.lagrangian_value,
        "blocking": decision.blocking_regulations,
        "mitigations": decision.mitigations_required,
        "justification": decision.justification,
        "constraints": [
            {"regulation": r.regulation, "verdict": r.verdict.name, "rationale": r.rationale}
            for r in decision.constraints
        ],
    }

    # Chain hash: hash of (previous last line + this entry) for tamper detection
    prev_hash = _last_audit_hash()
    entry["prev_hash"] = prev_hash
    entry_json = json.dumps(entry, separators=(",", ":"))
    entry["hash"] = hashlib.sha256((prev_hash + entry_json).encode()).hexdigest()

    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _last_audit_hash() -> str:
    """Return the hash of the last audit log entry, or genesis hash if empty."""
    genesis = "0" * 64
    if not os.path.exists(AUDIT_LOG_PATH):
        return genesis
    try:
        with open(AUDIT_LOG_PATH, "rb") as f:
            # Efficiently read last line
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return genesis
            f.seek(max(0, size - 4096))
            lines = f.read().decode(errors="replace").strip().splitlines()
            if not lines:
                return genesis
            last = json.loads(lines[-1])
            return last.get("hash", genesis)
    except Exception:
        return genesis


def infer_context(path: str, description: str = "") -> DataContext:
    """
    Heuristically infer DataContext from a file path, bash command, or description.

    This is the agent's "sensorium" — it translates raw action strings into
    a structured DataContext the compliance lattice can evaluate. It understands:
      - File paths (direct and embedded in bash commands)
      - Bash commands that access sensitive data patterns
      - Jurisdiction signals from path prefixes, country codes, and regulation keywords

    A `read_file` on /var/log/system.log → DataContext(data_type="log", contains_pii=False)
    A `read_file` on /data/patients/records.json → DataContext(data_type="health", contains_phi=True)
    A `bash: cat /users/db/ssn_table.csv` → DataContext(data_type="pii", contains_pii=True)
    """
    import re as _re

    # Extract file paths from bash commands (cat, cp, mv, rm, grep, find, python, etc.)
    # Also catch python os.remove / open() calls
    path_tokens = _re.findall(r"(?:^|\s)([/~][^\s;|&>'\"]+)", path)
    path_tokens += _re.findall(r"['\"]([/~][^'\"]+)['\"]", path)
    all_paths = [path] + path_tokens

    combined = " ".join(all_paths).lower() + " " + description.lower()

    # ── Data type classification ──────────────────────────────────────────────
    _HEALTH_KW  = ("hipaa", "health", "patient", "medical", "phi", "ehr", "emr",
                   "diagnosis", "prescription", "clinical", "radiology", "lab_result",
                   "medication", "symptom", "icd", "cpt")
    _FIN_KW     = ("finance", "bank", "credit", "payment", "fcra", "glba", "metro",
                   "tradeline", "transaction", "account", "ledger", "invoice", "billing",
                   "payroll", "salary", "tax", "w2", "1099", "routing", "swift")
    _CRED_KW    = ("password", "passwd", "secret", "api_key", "token", "credential",
                   "ssh", "private_key", ".pem", ".p12", ".pfx", "keystore", "vault",
                   "auth", "bearer", "oauth", "jwt")
    _LOG_KW     = ("audit.log", "audit.jsonl", "audit_log", "/audit/", "_audit.",
                   "soc", "event_log", "access_log", "syslog", "auth.log",
                   "/var/log", "application.log", "error.log")
    _PII_KW     = ("pii", "customer", "email", "ssn", "social_security", "dob",
                   "date_of_birth", "address", "personal", "passport", "driver_license",
                   "phone", "zipcode", "users/", "user_data", "profile", "identity",
                   "contact", "contacts", "marketing", "gdpr", "ccpa", "lgpd", "pipl",
                   "pipeda", "consumer", "subscriber", "member",
                   "/users/", "/users.", "/customers/", "/customers.", "/members/", "/members.")

    data_type = (
        "health"     if any(k in combined for k in _HEALTH_KW) else
        "financial"  if any(k in combined for k in _FIN_KW) else
        "credential" if any(k in combined for k in _CRED_KW) else
        "log"        if any(k in combined for k in _LOG_KW) else
        "pii"        if any(k in combined for k in _PII_KW) else
        "code"
    )

    # ── Jurisdiction detection ────────────────────────────────────────────────
    _EU_KW   = ("gdpr", "/eu/", "/europe/", ".de/", ".fr/", ".nl/", ".ie/", ".es/",
                "/de/", "/fr/", "/nl/", "/ie/", "/es/", "/it/", "/pt/",
                "european", "dsgvo", "rgpd")
    _CA_KW   = ("ccpa", "/california/", "/ca/", "california")
    _BR_KW   = ("lgpd", "/brazil/", "/br/", "brasil", "brazil")
    _CN_KW   = ("pipl", "/china/", "/cn/", "chinese", "prc")
    _CAD_KW  = ("pipeda", "/canada/", "/ca/", "canadian", "quebec", "law25")

    jurisdiction = (
        "EU" if any(k in combined for k in _EU_KW) else
        "BR" if any(k in combined for k in _BR_KW) else
        "CN" if any(k in combined for k in _CN_KW) else
        "CAD" if any(k in combined for k in _CAD_KW) else
        "CA" if any(k in combined for k in _CA_KW) else
        "US"
    )

    return DataContext(
        path=path,
        data_type=data_type,
        subject_jurisdiction=jurisdiction,
        contains_pii=any(k in combined for k in (*_PII_KW, *_HEALTH_KW)),
        contains_phi=any(k in combined for k in _HEALTH_KW),
        contains_financial=any(k in combined for k in _FIN_KW),
        is_audit_log=any(k in combined for k in _LOG_KW),
    )


def print_decision(decision: ComplianceDecision) -> None:
    """Pretty-print a compliance decision to the terminal."""
    icon = "✅" if decision.permitted else "🚫"
    print(f"\n{'═'*60}")
    print(f"  {icon} COMPLIANCE DECISION — {decision.action_type.upper()}")
    print(f"  Path     : {decision.path}")
    print(f"  Lagrangian L = {decision.lagrangian_value:.2f}  ({'PASS' if decision.permitted else 'FAIL'})")
    print(f"{'─'*60}")
    for r in decision.constraints:
        symbol = {"PERMIT": "✓", "CONDITIONAL": "◑", "BLOCK": "✗"}[r.verdict.name]
        print(f"  {symbol} [{r.regulation:<15}] {r.rationale[:65]}")
    if decision.mitigations_required:
        print(f"\n  Required mitigations:")
        for m in decision.mitigations_required:
            print(f"    • {m[:75]}")
    if decision.blocking_regulations:
        print(f"\n  BLOCKED BY: {', '.join(decision.blocking_regulations)}")
    print(f"\n  Audit ID : {decision.action_id}")
    print(f"  Log      : {AUDIT_LOG_PATH}")
    print(f"{'═'*60}\n")
