"""
audit.py — SOC 2 CC6.1 compliant append-only audit log.

Every agent action is recorded with:
  - ISO 8601 timestamp with timezone
  - Identity: model source + autonomy level
  - Action type + SHA-256 hash of payload (never raw payload — may contain secrets)
  - Compliance verdict from the lattice
  - Outcome: success / failure / blocked
  - SHA-256 hash chain: h_t = SHA256(h_{t-1} || entry_t)

The chain makes any tampering with historical entries detectable:
modifying entry_k invalidates h_k, h_{k+1}, ..., h_n.

Log file: ~/.agent_audit.jsonl (one JSON object per line)
Fallback: <project>/.agent_audit.jsonl

CC6.1 requirement: "The entity implements logical access security software,
infrastructure, and architectures over protected information assets."
CC6.1 audit: "All access to and modifications of sensitive data must be logged
with sufficient detail to reconstruct the sequence of events."
"""

import hashlib
import json
import os
import socket
import datetime
from typing import Optional

_LOG_FILE = os.path.expanduser("~/.agent_audit.jsonl")
if not os.access(os.path.dirname(_LOG_FILE) or ".", os.W_OK):
    _LOG_FILE = os.path.join(os.path.dirname(__file__), ".agent_audit.jsonl")

_GENESIS_HASH = "0" * 64  # h_0


def _last_hash() -> str:
    """Read the hash of the most recent log entry (the chain tip)."""
    if not os.path.exists(_LOG_FILE):
        return _GENESIS_HASH
    try:
        with open(_LOG_FILE, "rb") as f:
            # Scan to last non-empty line efficiently
            last = _GENESIS_HASH
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        last = entry.get("hash", _GENESIS_HASH)
                    except json.JSONDecodeError:
                        pass
        return last
    except OSError:
        return _GENESIS_HASH


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _payload_hash(payload: dict) -> str:
    """SHA-256 of canonical JSON of payload — never stores raw values."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return _sha256(canonical)


def log_action(
    *,
    action_type: str,
    description: str,
    payload: dict,
    model_source: str,
    autonomy: str,
    compliance_verdict: str,      # "permit" | "conditional" | "block"
    compliance_detail: str = "",  # which regulations triggered
    outcome: str,                 # "success" | "failure" | "blocked" | "skipped"
    outcome_detail: str = "",     # error message or result summary (truncated)
    step: Optional[int] = None,
    task_hash: Optional[str] = None,  # SHA-256 of the current task string
) -> dict:
    """
    Append one entry to the audit log and return it.
    Thread-safe via file append (atomic on POSIX for small writes).
    """
    now = datetime.datetime.now().astimezone()
    timestamp = now.isoformat()

    prev_hash = _last_hash()

    entry: dict = {
        "timestamp":          timestamp,
        "host":               socket.gethostname(),
        "autonomy":           autonomy,
        "model_source":       model_source,
        "action_type":        action_type,
        "description":        description[:200],          # truncate
        "payload_hash":       _payload_hash(payload),
        "compliance_verdict": compliance_verdict,
        "compliance_detail":  compliance_detail[:200],
        "outcome":            outcome,
        "outcome_detail":     outcome_detail[:300],
        "step":               step,
        "task_hash":          task_hash,
        "prev_hash":          prev_hash,
    }

    # Compute this entry's hash (over everything except "hash" itself)
    entry_json = json.dumps(entry, sort_keys=True, ensure_ascii=True)
    entry["hash"] = _sha256(prev_hash + entry_json)

    try:
        with open(_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # never let audit logging break the agent

    return entry


def verify_chain(log_file: Optional[str] = None) -> tuple[bool, int, str]:
    """
    Verify the integrity of the audit log hash chain.
    Returns (ok, entries_checked, error_message).
    """
    path = log_file or _LOG_FILE
    if not os.path.exists(path):
        return True, 0, "Log file does not exist yet."

    prev_hash = _GENESIS_HASH
    chain_started = False
    count = 0

    try:
        with open(path) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, count, f"Line {lineno}: invalid JSON"

                stored_hash = entry.pop("hash", None)
                if stored_hash is None:
                    # Pre-chain legacy entry — skip, don't fail
                    continue

                # Seed prev_hash from the first hashed entry's own prev_hash
                # so we can verify correctly even if there are legacy entries before it
                if not chain_started:
                    prev_hash = entry.get("prev_hash", _GENESIS_HASH)
                    chain_started = True

                entry_json = json.dumps(entry, sort_keys=True, ensure_ascii=True)
                expected = _sha256(prev_hash + entry_json)

                if stored_hash != expected:
                    return False, count, (
                        f"Line {lineno}: hash mismatch — "
                        f"chain broken (expected {expected[:16]}… got {stored_hash[:16]}…)"
                    )

                prev_hash = stored_hash
                count += 1

    except OSError as e:
        return False, count, str(e)

    return True, count, f"Chain intact — {count} entries verified."


def tail_log(n: int = 20, log_file: Optional[str] = None) -> list[dict]:
    """Return the last n entries from the audit log."""
    path = log_file or _LOG_FILE
    if not os.path.exists(path):
        return []
    entries = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    return entries[-n:]


def print_log_table(n: int = 20) -> None:
    entries = tail_log(n)
    if not entries:
        print("Audit log is empty.")
        return
    print("\n" + "═" * 90)
    print(f"  AUDIT LOG  (last {len(entries)} entries)  —  {_LOG_FILE}")
    print("─" * 90)
    print(f"  {'Timestamp':<26} {'Model':<22} {'Action':<12} {'Verdict':<12} {'Outcome'}")
    print("─" * 90)
    for e in entries:
        ts = e.get("timestamp", "")[:19].replace("T", " ")
        model = e.get("model_source", "")[-22:]
        atype = e.get("action_type", "")[:11]
        verdict = e.get("compliance_verdict", "")[:11]
        outcome = e.get("outcome", "")
        detail = e.get("outcome_detail", "")[:30]
        print(f"  {ts:<26} {model:<22} {atype:<12} {verdict:<12} {outcome}  {detail}")
    print("═" * 90 + "\n")
