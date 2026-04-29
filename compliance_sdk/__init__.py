"""
compliance_sdk — Tropical Compliance Lattice with n-Dot Braille Encoding

Compliance-as-a-service for AI agents. Drop-in pre-execution gate that
evaluates any proposed action against 9 regulatory frameworks (SOC II,
GDPR, CCPA, HIPAA, GLBA, FCRA, Metro II/CDIA, PIPL, ISO 27001) and
returns a Braille-encoded compliance verdict.

Quick start:
    from compliance_sdk import evaluate_action
    result = evaluate_action("bash", "rm -rf /data/eu/users/profiles.json")

    result.permitted          # False
    result.braille_word       # '⠑⠃'  (2-cell ternary Braille word)
    result.lagrangian         # 2.0
    result.blocking           # ['GDPR', 'ISO-27001']

HTTP API (start with `python -m compliance_sdk.server`):
    POST /evaluate    — evaluate a single action
    POST /filtration  — progressive regulatory tier evaluation
    POST /bridge      — compare/merge multiple Braille words
    GET  /audit       — tamper-evident audit log
"""

from __future__ import annotations

import sys
import os

# Ensure the parent directory (containing compliance.py) is importable
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from compliance import (
    # Core evaluation
    evaluate as _evaluate,
    infer_context as _infer_context,
    DataContext,
    ComplianceDecision,
    Verdict,
    ConstraintResult,

    # Braille encoding
    encode_braille_word,
    decode_braille_word,
    encode_braille_binary,
    braille_word_to_bits,
    ndot_dimension,
    BrailleWord,
    REGULATION_ORDER,

    # Lattice bridge operations
    braille_meet,
    braille_join,
    braille_hamming,
    braille_drift,
    bridge_model_states,
    project_to_braille,

    # Filtration
    evaluate_filtration,
    FiltrationTier,
)

__all__ = [
    # High-level API
    "evaluate_action",
    "evaluate_action_with_context",
    "ActionResult",

    # Core types
    "DataContext",
    "ComplianceDecision",
    "Verdict",
    "ConstraintResult",
    "BrailleWord",
    "FiltrationTier",

    # Braille encoding
    "encode_braille_word",
    "decode_braille_word",
    "encode_braille_binary",
    "braille_word_to_bits",
    "ndot_dimension",
    "REGULATION_ORDER",

    # Lattice bridge
    "braille_meet",
    "braille_join",
    "braille_hamming",
    "braille_drift",
    "bridge_model_states",
    "project_to_braille",

    # Filtration
    "evaluate_filtration",
]

__version__ = "0.1.0"


# ─── High-level convenience API ─────────────────────────────────────────────

class ActionResult:
    """
    Simplified result object for the high-level evaluate_action() API.

    Attributes:
        permitted (bool): True if no regulation blocks the action.
        braille_word (str): 2-cell Unicode Braille word encoding the full verdict vector.
        braille_binary (str): Single-cell 8-dot binary encoding (permit/block only).
        lagrangian (float): Tropical max score. 0.0 = all clear, >0 = issues.
        verdict (str): 'PERMIT', 'CONDITIONAL', or 'BLOCK'.
        blocking (list[str]): Regulation names that block the action.
        mitigations (list[str]): Required mitigations for conditional verdicts.
        constraints (list[ConstraintResult]): Per-regulation verdict details.
        action_id (str): Unique ID for audit log correlation.
        bits (str): Raw bit string of the Braille word (for debugging).
        state_int (int): Integer encoding of the verdict vector.
        justification (str): Human-readable justification string.
        decision (ComplianceDecision): Full decision object for advanced use.
    """

    def __init__(self, decision: ComplianceDecision, braille: BrailleWord, binary: str):
        self.decision = decision
        self.permitted = decision.permitted
        self.lagrangian = decision.lagrangian_value
        self.blocking = decision.blocking_regulations
        self.mitigations = decision.mitigations_required
        self.constraints = decision.constraints
        self.action_id = decision.action_id
        self.justification = decision.justification

        # Braille encoding
        self.braille_word = braille.word
        self.braille_binary = binary
        self.bits = braille_word_to_bits(braille.word)
        self.state_int = braille.state_int
        self.cells = braille.cells
        self.framework_count = braille.framework_count
        self.states_per_framework = braille.states_per_framework

        # Verdict string
        if not decision.permitted:
            self.verdict = "BLOCK"
        elif decision.mitigations_required:
            self.verdict = "CONDITIONAL"
        else:
            self.verdict = "PERMIT"

    def __repr__(self):
        return (f"ActionResult(verdict={self.verdict!r}, braille={self.braille_word!r}, "
                f"ℒ={self.lagrangian:.2f}, blocking={self.blocking})")

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict for API responses."""
        return {
            "permitted": self.permitted,
            "verdict": self.verdict,
            "lagrangian": self.lagrangian,
            "braille_word": self.braille_word,
            "braille_binary": self.braille_binary,
            "bits": self.bits,
            "state_int": self.state_int,
            "cells": self.cells,
            "blocking": self.blocking,
            "mitigations": self.mitigations,
            "justification": self.justification,
            "action_id": self.action_id,
            "constraints": [
                {"regulation": c.regulation, "verdict": c.verdict.name, "rationale": c.rationale}
                for c in self.constraints
            ],
        }


def evaluate_action(action_type: str, path_or_command: str,
                    description: str = "") -> ActionResult:
    """
    Evaluate a proposed agent action against the full compliance lattice.

    This is the primary entry point for agent frameworks. Call this before
    executing any action. Context (jurisdiction, data type, PII/PHI flags)
    is auto-inferred from the path/command string.

    Args:
        action_type: One of 'bash', 'python_exec', 'write_file', 'read_file',
                     'pyautogui', 'playwright', 'noop'.
        path_or_command: The file path, bash command, or code to evaluate.
        description: Optional human-readable description for better inference.

    Returns:
        ActionResult with .permitted, .braille_word, .lagrangian, .verdict, etc.

    Example:
        >>> from compliance_sdk import evaluate_action
        >>> r = evaluate_action("bash", "rm -rf /data/eu/users/profiles.json")
        >>> r.permitted
        False
        >>> r.braille_word
        '⠑⠃'
        >>> r.verdict
        'BLOCK'
    """
    ctx = _infer_context(path_or_command, description)
    payload = {"command": path_or_command, "path": path_or_command}
    decision = _evaluate(action_type, payload, ctx)
    bw = encode_braille_word(decision.constraints)
    bb = encode_braille_binary(decision.constraints)
    return ActionResult(decision, bw, bb)


def evaluate_action_with_context(action_type: str, path_or_command: str,
                                  context: DataContext) -> ActionResult:
    """
    Evaluate with an explicit DataContext (no auto-inference).

    Use this when you know the exact data classification, jurisdiction,
    and flags — e.g., from your own data catalog or policy engine.

    Args:
        action_type: Action type string.
        path_or_command: The file path or command.
        context: Explicit DataContext with all fields set.

    Returns:
        ActionResult.
    """
    payload = {"command": path_or_command, "path": path_or_command}
    decision = _evaluate(action_type, payload, context)
    bw = encode_braille_word(decision.constraints)
    bb = encode_braille_binary(decision.constraints)
    return ActionResult(decision, bw, bb)
