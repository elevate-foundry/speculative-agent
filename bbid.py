"""
bbid.py — BrailleBuddy Identity for the Speculative Agent
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Generates a deterministic 8-character Braille identity (64 bits of entropy)
for this agent instance. The BBID travels alongside the compliance Braille
word in every audit log entry, API response, and message queue payload.

Together:
    BBID  = WHO   (8 Braille chars, agent/device identity)
    Word  = WHAT  (2 Braille chars, compliance verdict)

Both are pure UTF-8 strings — no encoding overhead, grep-able in logs.

Based on the BBID spec from Elevate Foundry (bbid-specification.md).
"""

import hashlib
import hmac
import os
import platform
import socket
import uuid
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

BRAILLE_BASE = 0x2800
_BBID_FILE = os.path.join(os.path.dirname(__file__), ".bbid.json")
_BBID_KEY = os.environ.get("BBID_KEY", "speculative-agent-bbid-v1")


@dataclass
class BBID:
    """BrailleBuddy Identity — 8 Braille characters."""
    braille: str                # 8 × 8-dot Braille chars (64 bits identity)
    agent_id: str               # UUID for this agent instance
    hostname: str               # machine hostname
    created_at: str             # ISO 8601
    signature: str              # HMAC-SHA256 as 8 Braille chars
    platform: str = ""          # e.g. "macOS-15.3-arm64"
    python_version: str = ""    # e.g. "3.10.12"

    @property
    def display(self) -> str:
        """Short display: ⟨bbid:⠁⠃⠅⠇⠉⠋⠙⠛⟩"""
        return f"⟨bbid:{self.braille}⟩"

    @property
    def short(self) -> str:
        """First 4 Braille chars — enough for visual identification in logs."""
        return self.braille[:4]

    @property
    def haptic_pattern(self) -> list[dict]:
        """Generate haptic pattern for rendering this BBID on mobile devices."""
        patterns = []
        for char in self.braille:
            code = ord(char) - BRAILLE_BASE
            dot_count = bin(code).count("1")
            patterns.append({
                "duration_ms": 50 + (dot_count * 20),
                "intensity": round(0.3 + (dot_count * 0.1), 2),
            })
            patterns.append({"type": "pause", "duration_ms": 100})
        return patterns

    def to_dict(self) -> dict:
        return asdict(self)


def _sign(braille: str, agent_id: str) -> str:
    """HMAC-SHA256 signature encoded as 8 Braille characters."""
    message = f"{braille}:{agent_id}".encode()
    sig = hmac.new(_BBID_KEY.encode(), message, hashlib.sha256).hexdigest()
    return "".join(
        chr(BRAILLE_BASE + int(sig[i:i + 2], 16))
        for i in range(0, 16, 2)
    )


def _generate_fingerprint() -> bytes:
    """
    Deterministic machine fingerprint from stable hardware/software signals.
    Same machine + same user → same fingerprint across sessions.
    """
    components = [
        socket.gethostname(),
        platform.platform(),
        platform.machine(),
        platform.processor(),
        str(os.cpu_count()),
        os.environ.get("USER", os.environ.get("USERNAME", "")),
        # MAC address of primary interface (stable across reboots)
        hex(uuid.getnode()),
    ]
    seed = "|".join(components)
    return hashlib.sha256(seed.encode()).digest()


def generate_bbid(name: Optional[str] = None) -> BBID:
    """
    Generate a new BBID for this agent instance.
    Deterministic for the same machine — calling twice returns the same identity.
    """
    fingerprint = _generate_fingerprint()

    # 8 Braille characters from the first 8 bytes of the fingerprint hash
    braille_chars = []
    for i in range(8):
        braille_chars.append(chr(BRAILLE_BASE + fingerprint[i]))
    braille = "".join(braille_chars)

    # Stable agent UUID derived from fingerprint (UUID5 with DNS namespace)
    agent_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, braille))

    signature = _sign(braille, agent_id)

    return BBID(
        braille=braille,
        agent_id=agent_id,
        hostname=socket.gethostname(),
        created_at=datetime.now(timezone.utc).isoformat(),
        signature=signature,
        platform=platform.platform(),
        python_version=platform.python_version(),
    )


def verify_bbid(bbid: BBID) -> bool:
    """Verify the HMAC signature of a BBID."""
    expected = _sign(bbid.braille, bbid.agent_id)
    return hmac.compare_digest(
        bbid.signature.encode("utf-8"), expected.encode("utf-8")
    )


def load_or_create() -> BBID:
    """
    Load the saved BBID for this machine, or generate and save a new one.
    The BBID is stable — same machine always gets the same identity.
    """
    if os.path.exists(_BBID_FILE):
        try:
            with open(_BBID_FILE) as f:
                data = json.load(f)
            bbid = BBID(**data)
            if verify_bbid(bbid):
                return bbid
            # Signature invalid — regenerate
        except Exception:
            pass

    bbid = generate_bbid()
    try:
        with open(_BBID_FILE, "w") as f:
            json.dump(bbid.to_dict(), f, indent=2)
    except Exception:
        pass  # read-only filesystem etc.
    return bbid


def bbid_header(bbid: BBID, compliance_word: str = "") -> str:
    """
    Format a compact header for logs / API responses.

    Example:
        ⟨bbid:⠁⠃⠅⠇⠉⠋⠙⠛⟩ ⟨verdict:⢤⠙⟩
    """
    parts = [bbid.display]
    if compliance_word:
        parts.append(f"⟨verdict:{compliance_word}⟩")
    return " ".join(parts)


# ─── Module-level singleton ─────────────────────────────────────────────────

_INSTANCE: Optional[BBID] = None


def get_bbid() -> BBID:
    """Get the global BBID for this agent process (lazy singleton)."""
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = load_or_create()
    return _INSTANCE


if __name__ == "__main__":
    bbid = get_bbid()
    print(f"BBID     : {bbid.display}")
    print(f"Braille  : {bbid.braille}")
    print(f"Agent ID : {bbid.agent_id}")
    print(f"Hostname : {bbid.hostname}")
    print(f"Platform : {bbid.platform}")
    print(f"Signature: {bbid.signature}")
    print(f"Verified : {verify_bbid(bbid)}")
    print(f"Haptic   : {len(bbid.haptic_pattern)} steps")
    print(f"\nStored at: {_BBID_FILE}")

    # Demo: combined header with a compliance word
    from compliance_sdk import evaluate_action
    r = evaluate_action("bash", "rm /data/eu/users.json")
    print(f"\n{bbid_header(bbid, r.braille_word)}")
