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
    braille_word: str = ""           # n-dot ternary encoding (multi-cell)
    braille_binary: str = ""         # 8-dot binary encoding (single-cell)


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

    # Braille encoding — computed lazily here to avoid circular import
    try:
        _bw = encode_braille_word(results)
        _bb = encode_braille_binary(results)
    except Exception:
        _bw = None
        _bb = ""

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
        braille_word=_bw.word if _bw else "",
        braille_binary=_bb,
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
        "braille_word": decision.braille_word,
        "braille_binary": decision.braille_binary,
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
    # Braille encoding
    braille = encode_braille_word(decision.constraints)
    binary_cell = encode_braille_binary(decision.constraints)
    print(f"\n  Braille  : {braille.word}  (ternary, {braille.cells}-cell, {braille.bits_required}b)")
    print(f"  Binary   : {binary_cell}  (8-dot, permit/block only)")
    print(f"  Audit ID : {decision.action_id}")
    print(f"  Log      : {AUDIT_LOG_PATH}")
    print(f"{'═'*60}\n")


# ─── n-Dot Hyper-Braille Encoding ───────────────────────────────────────────
#
# Mathematical foundation:
#   To encode F frameworks × S states per framework, we need:
#     d = ⌈F · log₂(S)⌉ bits
#   Each 8-dot Braille cell holds 8 bits (Unicode U+2800–U+28FF).
#   Required cells: ⌈d / 8⌉
#
#   Current system: F=9 frameworks, S=3 states (Permit/Conditional/Block)
#     d = ⌈9 · log₂(3)⌉ = ⌈9 · 1.5849⌉ = 15 bits
#     cells = ⌈15 / 8⌉ = 2 cells → a two-character Braille "word"
#
# The encoding preserves the tropical lattice structure:
#   - The all-Permit state (0,0,...,0) maps to ⠀⠀ (Braille space × 2)
#   - Any raised dot signals a non-Permit verdict
#   - The word's integer value equals the mixed-radix compliance vector
#
# Backward compatibility:
#   encode_braille_binary() provides the original 8-dot single-cell encoding
#   for the binary (Permit/Block) case, fitting in U+2800–U+28FF.
# ─────────────────────────────────────────────────────────────────────────────

import math as _math


# Verdict → ternary digit: Permit=0, Conditional=1, Block=2
_VERDICT_TO_TRIT = {
    Verdict.PERMIT:      0,
    Verdict.CONDITIONAL: 1,
    Verdict.BLOCK:       2,
}
_TRIT_TO_VERDICT = {v: k for k, v in _VERDICT_TO_TRIT.items()}

# Canonical regulation ordering (matches _CONSTRAINTS list and dot assignments)
REGULATION_ORDER = [
    "SOC-II", "GDPR", "CCPA", "HIPAA", "GLBA",
    "FCRA", "Metro-II/CDIA", "PIPL", "ISO-27001",
]


@dataclass
class BrailleWord:
    """A multi-cell Braille encoding of a compliance decision vector."""
    word: str                # Unicode Braille string (1+ characters)
    cells: int               # number of 8-dot cells used
    bits_required: int       # theoretical bits needed (d = ⌈F·log₂S⌉)
    bits_available: int      # actual bits (cells × 8)
    state_int: int           # integer encoding of the compliance vector
    framework_count: int     # F
    states_per_framework: int  # S


def ndot_dimension(frameworks: int, states: int = 3) -> int:
    """
    Compute d = ⌈F · log₂(S)⌉ — the exact bit-dimension required to
    encode F frameworks with S states each.
    """
    if states <= 1:
        return 0
    return _math.ceil(frameworks * _math.log2(states))


def encode_braille_word(constraints: list[ConstraintResult],
                        states: int = 3) -> BrailleWord:
    """
    Encode a compliance decision vector as a multi-cell Braille word.

    Maps each framework's verdict to a trit (0/1/2), packs them into a
    mixed-radix integer, then splits into 8-bit chunks, each rendered as
    a Unicode Braille character (U+2800 + byte_value).

    For 9 ternary frameworks: 2-cell word (16 bits available, 15 needed).
    The all-PERMIT state encodes to ⠀⠀ (two Braille spaces).
    """
    F = len(constraints)
    d = ndot_dimension(F, states)
    cells_needed = max(1, _math.ceil(d / 8))

    # Mixed-radix encoding: state_int = Σ trit_i · S^i
    state_int = 0
    for i, cr in enumerate(constraints):
        trit = _VERDICT_TO_TRIT.get(cr.verdict, 0)
        state_int += trit * (states ** i)

    # Pack into 8-bit Braille cells (little-endian byte order)
    word = ""
    val = state_int
    for _ in range(cells_needed):
        byte_val = val & 0xFF
        word += chr(0x2800 + byte_val)
        val >>= 8

    return BrailleWord(
        word=word,
        cells=cells_needed,
        bits_required=d,
        bits_available=cells_needed * 8,
        state_int=state_int,
        framework_count=F,
        states_per_framework=states,
    )


def decode_braille_word(word: str, framework_count: int = 9,
                        states: int = 3) -> list[Verdict]:
    """
    Decode a Braille word back to a list of Verdict values.
    Inverse of encode_braille_word.
    """
    # Reconstruct integer from Braille cells
    state_int = 0
    for i, ch in enumerate(word):
        byte_val = ord(ch) - 0x2800
        if not (0 <= byte_val <= 255):
            raise ValueError(f"Character {ch!r} is not a valid Braille pattern")
        state_int |= byte_val << (8 * i)

    # Unpack mixed-radix digits
    verdicts = []
    for _ in range(framework_count):
        trit = state_int % states
        verdicts.append(_TRIT_TO_VERDICT.get(trit, Verdict.PERMIT))
        state_int //= states

    return verdicts


def encode_braille_binary(constraints: list[ConstraintResult]) -> str:
    """
    Original 8-dot encoding for the binary case (Permit=0, Block=1).
    CONDITIONAL is mapped to Block (raised dot) for the binary view.
    Returns a single Unicode Braille character.

    Backward-compatible with the paper's Theorem 4.1 (Braille–Compliance
    Isomorphism) for k ≤ 8 frameworks. For k > 8, returns multi-cell.
    """
    bits = 0
    for i, cr in enumerate(constraints):
        if cr.verdict != Verdict.PERMIT:
            bits |= (1 << i)

    if bits <= 0xFF:
        return chr(0x2800 + bits)

    # k > 8: multi-cell binary encoding
    word = ""
    val = bits
    cells = _math.ceil(len(constraints) / 8)
    for _ in range(cells):
        word += chr(0x2800 + (val & 0xFF))
        val >>= 8
    return word


def braille_word_to_bits(word: str) -> str:
    """Return the raw bit string of a Braille word (for debugging/display)."""
    bits = []
    for ch in word:
        byte_val = ord(ch) - 0x2800
        bits.append(format(byte_val, '08b'))
    return " ".join(bits)


# ─── Lattice Operations on Braille Words (Model State Bridge) ────────────────
#
# Two models produce verdict vectors v_A, v_B ∈ {0,1,2}^F.
# Their Braille words w_A, w_B are mixed-radix integers.
#
# The lattice operations on the verdict space are:
#   meet(v_A, v_B)_i = max(v_A_i, v_B_i)  — conservative (take strictest)
#   join(v_A, v_B)_i = min(v_A_i, v_B_i)  — permissive (take most lenient)
#
# In the tropical semiring (max-plus):
#   meet = tropical addition (max)
#   join = tropical multiplication (min under the dual)
#
# This gives us a principled way to bridge any two models' state spaces:
#   1. Project each model's output through the compliance lattice → verdict vector
#   2. Encode each verdict vector as a Braille word
#   3. Use meet/join/distance to merge, compare, or translate between them
# ─────────────────────────────────────────────────────────────────────────────

def braille_meet(word_a: str, word_b: str,
                 framework_count: int = 9, states: int = 3) -> str:
    """
    Conservative merge of two Braille words.
    Takes the strictest (max) verdict per framework.
    meet(P,C)=C, meet(C,B)=B, meet(P,B)=B.

    In the tropical semiring: this is tropical addition (⊕ = max).
    If either model says BLOCK, the merged result is BLOCK.
    """
    va = decode_braille_word(word_a, framework_count, states)
    vb = decode_braille_word(word_b, framework_count, states)

    # max over trit values: PERMIT=0 < CONDITIONAL=1 < BLOCK=2
    merged = []
    for a, b in zip(va, vb):
        ta = _VERDICT_TO_TRIT[a]
        tb = _VERDICT_TO_TRIT[b]
        merged.append(ConstraintResult("merged", _TRIT_TO_VERDICT[max(ta, tb)], "meet"))

    return encode_braille_word(merged, states).word


def braille_join(word_a: str, word_b: str,
                 framework_count: int = 9, states: int = 3) -> str:
    """
    Permissive merge of two Braille words.
    Takes the most lenient (min) verdict per framework.
    join(P,C)=P, join(C,B)=C, join(P,B)=P.

    In the tropical semiring: this is the dual operation (min).
    Both models must agree on BLOCK for the merged result to be BLOCK.
    """
    va = decode_braille_word(word_a, framework_count, states)
    vb = decode_braille_word(word_b, framework_count, states)

    merged = []
    for a, b in zip(va, vb):
        ta = _VERDICT_TO_TRIT[a]
        tb = _VERDICT_TO_TRIT[b]
        merged.append(ConstraintResult("merged", _TRIT_TO_VERDICT[min(ta, tb)], "join"))

    return encode_braille_word(merged, states).word


def braille_hamming(word_a: str, word_b: str,
                    framework_count: int = 9, states: int = 3) -> int:
    """
    Hamming distance between two Braille words in verdict space.
    Counts the number of frameworks where the two models disagree.
    Range: 0 (identical) to F (total disagreement).
    """
    va = decode_braille_word(word_a, framework_count, states)
    vb = decode_braille_word(word_b, framework_count, states)
    return sum(1 for a, b in zip(va, vb) if a != b)


def braille_drift(word_a: str, word_b: str,
                  framework_count: int = 9, states: int = 3) -> float:
    """
    Weighted drift between two Braille words.
    Like Hamming distance but weighted by trit difference magnitude.
    Range: 0.0 (identical) to 1.0 (maximal divergence: all P↔B).

    Useful for detecting when two models' compliance views are diverging
    beyond a threshold — triggering re-evaluation or human review.
    """
    va = decode_braille_word(word_a, framework_count, states)
    vb = decode_braille_word(word_b, framework_count, states)
    max_drift = framework_count * (states - 1)  # F * 2 for ternary
    if max_drift == 0:
        return 0.0
    total = sum(abs(_VERDICT_TO_TRIT[a] - _VERDICT_TO_TRIT[b]) for a, b in zip(va, vb))
    return total / max_drift


def project_to_braille(action_type: str, payload: dict,
                       context: "DataContext") -> BrailleWord:
    """
    Project any action through the compliance lattice into a Braille word.

    This is the fundamental bridge operation: regardless of which model
    proposed the action, the compliance lattice maps it to a canonical
    verdict vector in {Permit, Conditional, Block}^F, which then encodes
    as a Braille word.

    Two different models proposing the same action get the same Braille word.
    Two different models proposing different actions get comparable words
    that can be merged with meet/join or measured with hamming/drift.
    """
    decision = evaluate(action_type, payload, context)
    return encode_braille_word(decision.constraints)


def bridge_model_states(
    streams: list,
    task_context: "DataContext",
    verbose: bool = False,
) -> dict:
    """
    Bridge multiple models' state spaces through the Braille lattice.

    Given a list of ModelStream objects (from a race), extract each model's
    proposed action, project through the compliance lattice, and return:
      - Per-model Braille words
      - Pairwise Hamming distances and drift scores
      - Conservative merge (meet) and permissive merge (join) of all models
      - Consensus flag (all words identical)

    This enables:
      1. Detecting disagreement between models on compliance
      2. Choosing between models based on their compliance profile
      3. Merging multiple models' views into a single verdict
      4. Measuring drift over time as models evolve
    """
    from executor import parse_action_from_text

    words = {}
    for s in streams:
        if not s.text:
            continue
        action = parse_action_from_text(s.text, s.model_name)
        if action is None:
            continue
        bw = project_to_braille(
            action.action_type, action.payload, task_context)
        words[s.model_name] = bw

    if not words:
        return {"words": {}, "consensus": True, "pairwise": {},
                "meet": None, "join": None}

    names = list(words.keys())
    braille_strings = {n: w.word for n, w in words.items()}

    # Pairwise distances
    pairwise = {}
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            h = braille_hamming(braille_strings[a], braille_strings[b])
            d = braille_drift(braille_strings[a], braille_strings[b])
            pairwise[(a, b)] = {"hamming": h, "drift": round(d, 4)}

    # Consensus: all words identical
    word_set = set(braille_strings.values())
    consensus = len(word_set) == 1

    # Global meet (conservative) and join (permissive) across all models
    meet_word = braille_strings[names[0]]
    join_word = braille_strings[names[0]]
    for n in names[1:]:
        meet_word = braille_meet(meet_word, braille_strings[n])
        join_word = braille_join(join_word, braille_strings[n])

    if verbose:
        print(f"\n[bridge] {len(words)} models projected through Braille lattice")
        for n, w in words.items():
            print(f"  {n:<30}  {w.word}  state={w.state_int}")
        if pairwise:
            print(f"  Pairwise distances:")
            for (a, b), d in pairwise.items():
                a_short = a.split("/")[-1][:16]
                b_short = b.split("/")[-1][:16]
                print(f"    {a_short} ↔ {b_short}:  hamming={d['hamming']}  drift={d['drift']:.3f}")
        print(f"  Consensus: {'✓' if consensus else '✗ DIVERGENT'}")
        print(f"  Meet (conservative): {meet_word}   Join (permissive): {join_word}")

    return {
        "words": {n: w.word for n, w in words.items()},
        "state_ints": {n: w.state_int for n, w in words.items()},
        "consensus": consensus,
        "pairwise": pairwise,
        "meet": meet_word,
        "join": join_word,
    }


# ─── Lattice Filtration ─────────────────────────────────────────────────────
#
# A "filtration" is a nested sequence of sub-lattices:
#   F₁ ⊆ F₂ ⊆ ... ⊆ Fₖ
#
# In our system each Fᵢ is a set of active regulations. Adding a regulation
# can only raise (never lower) the verdict for each framework position,
# because a regulation either contributes a non-PERMIT verdict or PERMIT
# (which changes nothing). This gives the monotonicity property:
#
#   v(Fᵢ) ≤ v(Fᵢ₊₁)  componentwise (in the {P=0, C=1, B=2} order)
#
# Equivalently, the Braille words form a chain under the lattice partial order:
#   w(F₁) ≤ w(F₂) ≤ ... ≤ w(Fₖ)
#
# This is what "FCRA-abiding vs FCRA+GLBA-abiding vs full-lattice" means:
# each tier is a point on this chain, and the Braille word at each tier
# encodes exactly which regulations are active and what they say.
# ─────────────────────────────────────────────────────────────────────────────

# Map regulation names to their constraint functions
_CONSTRAINT_BY_NAME = {
    "SOC-II":       _check_soc,
    "GDPR":         _check_gdpr,
    "CCPA":         _check_ccpa,
    "HIPAA":        _check_hipaa,
    "GLBA":         _check_glba,
    "FCRA":         _check_fcra,
    "Metro-II/CDIA": _check_metro2_cdia,
    "PIPL":         _check_pipl,
    "ISO-27001":    _check_iso27001,
}

# Payload-aware constraints (need the payload argument)
_PAYLOAD_CONSTRAINTS = {_check_soc, _check_gdpr, _check_ccpa, _check_iso27001}


@dataclass
class FiltrationTier:
    """One level in a lattice filtration."""
    regulations: list[str]          # active regulations at this tier
    constraints: list[ConstraintResult]  # per-regulation verdicts
    braille: BrailleWord            # n-dot encoding of this tier
    lagrangian: float               # tropical max of λᵢ·vᵢ
    permitted: bool                 # no BLOCKs at this tier
    blocking: list[str]             # which regulations BLOCK at this tier


def evaluate_filtration(
    action_type: str,
    payload: dict,
    context: "DataContext",
    tiers: list[list[str]] = None,
    verbose: bool = False,
) -> list[FiltrationTier]:
    """
    Evaluate an action at progressively higher compliance tiers.

    Each tier is a list of regulation names. The default tiers are:
      1. FCRA only
      2. FCRA + GLBA
      3. FCRA + GLBA + SOC-II
      4. FCRA + GLBA + SOC-II + HIPAA
      5. FCRA + GLBA + SOC-II + HIPAA + GDPR + CCPA
      6. Full lattice (all 9 regulations)

    Returns a list of FiltrationTier objects forming a monotonic chain.
    The Braille word at tier i is componentwise ≤ the word at tier i+1.
    """
    if tiers is None:
        tiers = [
            ["FCRA"],
            ["FCRA", "GLBA"],
            ["FCRA", "GLBA", "SOC-II"],
            ["FCRA", "GLBA", "SOC-II", "HIPAA"],
            ["FCRA", "GLBA", "SOC-II", "HIPAA", "GDPR", "CCPA"],
            list(REGULATION_ORDER),  # full lattice
        ]

    results = []
    for tier_regs in tiers:
        # Evaluate only the constraints in this tier
        constraints = []
        for reg in REGULATION_ORDER:
            if reg in tier_regs:
                fn = _CONSTRAINT_BY_NAME[reg]
                if fn in _PAYLOAD_CONSTRAINTS:
                    cr = fn(context, action_type, payload)
                else:
                    cr = fn(context, action_type)
                constraints.append(cr)
            else:
                # Regulation not active at this tier → PERMIT (no constraint)
                constraints.append(ConstraintResult(reg, Verdict.PERMIT,
                                                    f"{reg} not active at this tier"))

        bw = encode_braille_word(constraints)
        lagrangian = max(
            (r.lagrangian_lambda * r.verdict.lagrangian_weight for r in constraints),
            default=0.0)
        blocking = [r.regulation for r in constraints if r.verdict == Verdict.BLOCK]

        tier = FiltrationTier(
            regulations=tier_regs,
            constraints=constraints,
            braille=bw,
            lagrangian=lagrangian,
            permitted=len(blocking) == 0,
            blocking=blocking,
        )
        results.append(tier)

    if verbose:
        print(f"\n{'═'*72}")
        print(f"  LATTICE FILTRATION — {action_type} on {context.path}")
        print(f"{'─'*72}")
        prev_word = None
        for i, t in enumerate(results):
            regs_str = "+".join(t.regulations)
            icon = "✓" if t.permitted else "✗"
            mono = ""
            if prev_word is not None:
                # Verify monotonicity
                prev_v = decode_braille_word(prev_word, len(REGULATION_ORDER))
                curr_v = decode_braille_word(t.braille.word, len(REGULATION_ORDER))
                mono_ok = all(
                    _VERDICT_TO_TRIT[curr_v[j]] >= _VERDICT_TO_TRIT[prev_v[j]]
                    for j in range(len(REGULATION_ORDER)))
                mono = " ≥ prev ✓" if mono_ok else " ≥ prev ✗ VIOLATION"
            print(f"  F{i}: {t.braille.word}  ℒ={t.lagrangian:.2f}  "
                  f"{icon}  [{regs_str}]{mono}")
            if t.blocking:
                print(f"      BLOCKED: {', '.join(t.blocking)}")
            prev_word = t.braille.word
        print(f"{'═'*72}\n")

    return results
