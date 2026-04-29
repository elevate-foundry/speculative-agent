# compliance-lattice

Tropical compliance lattice with n-dot Braille encoding.
Compliance-as-a-service for AI agents.

## Install

```bash
pip install -e .
```

## Python SDK — 3 lines to compliance-gate any agent

```python
from compliance_sdk import evaluate_action

# Before executing any action:
result = evaluate_action("bash", "rm -rf /data/eu/users/profiles.json")

result.permitted       # False
result.verdict         # 'BLOCK'
result.braille_word    # '⠑⠃'  (2-cell ternary Braille word)
result.lagrangian      # 2.0
result.blocking        # ['GDPR', 'ISO-27001']
result.bits            # '10001000 00000011'
result.state_int       # 6561
```

### LangChain integration

```python
from compliance_sdk import evaluate_action

def compliance_gate(action_type: str, command: str) -> bool:
    """Drop-in pre-execution gate for any agent framework."""
    r = evaluate_action(action_type, command)
    if not r.permitted:
        raise RuntimeError(f"Compliance BLOCK: {r.blocking} — {r.justification}")
    return True

# In your agent loop:
compliance_gate("bash", tool_input)
execute(tool_input)
```

### With explicit context

```python
from compliance_sdk import evaluate_action_with_context, DataContext

ctx = DataContext(
    path="/data/patient_records.json",
    contains_phi=True,
    subject_jurisdiction="US",
    created_days_ago=500,
)
result = evaluate_action_with_context("bash", "rm /data/patient_records.json", ctx)
# result.verdict == 'BLOCK' (HIPAA 6-year retention)
```

### Braille word operations — bridge model state spaces

```python
from compliance_sdk import (
    braille_meet, braille_join, braille_hamming, braille_drift,
    evaluate_action,
)

# Two models propose different actions:
r1 = evaluate_action("bash", "rm /data/eu/user.json")
r2 = evaluate_action("bash", "rm /data/us/credit.csv")

# Conservative merge (strictest per framework):
safe = braille_meet(r1.braille_word, r2.braille_word)

# How much do they disagree?
dist = braille_hamming(r1.braille_word, r2.braille_word)  # 0-9
drift = braille_drift(r1.braille_word, r2.braille_word)   # 0.0-1.0
```

### Filtration — progressive regulatory hardening

```python
from compliance_sdk import evaluate_filtration, DataContext

ctx = DataContext(path="/data/credit.csv", contains_financial=True, data_type="credit")
tiers = evaluate_filtration("bash", {"command": "rm /data/credit.csv"}, ctx, verbose=True)

# Output:
# F0: ⠀⠀  ℒ=0.00  ✓  [FCRA]
# F1: ⠀⠀  ℒ=0.00  ✓  [FCRA+GLBA]                    ≥ prev ✓
# F2: ⠀⠀  ℒ=0.00  ✓  [FCRA+GLBA+SOC-II]              ≥ prev ✓
# ...
# Each tier's Braille word is componentwise ≥ the previous (monotonic chain)
```

## HTTP API

Start the server:

```bash
python compliance_server.py
# → http://localhost:8420
```

### POST /evaluate — evaluate a single action

```bash
curl -X POST http://localhost:8420/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "action_type": "bash",
    "path": "rm -rf /data/eu/users/profiles.json"
  }'
```

Response:
```json
{
  "permitted": false,
  "lagrangian_value": 1.0,
  "braille": {
    "word": "⠑⠃",
    "binary": "⠑",
    "bits": "10001000 00000011",
    "state_int": 6561,
    "cells": 2,
    "bits_required": 15,
    "bits_available": 16,
    "framework_count": 9,
    "states_per_framework": 3
  },
  "blocking_regulations": ["GDPR"],
  "constraints": [...]
}
```

### POST /filtration — progressive regulatory tier evaluation

```bash
curl -X POST http://localhost:8420/filtration \
  -H 'Content-Type: application/json' \
  -d '{
    "action_type": "bash",
    "path": "rm /data/credit_report.csv",
    "contains_financial": true,
    "data_type": "credit"
  }'
```

Response:
```json
{
  "tiers": [
    {"regulations": ["FCRA"], "braille": {"word": "⠀⠀", "state_int": 0}, "permitted": true},
    {"regulations": ["FCRA","GLBA"], "braille": {"word": "⠐⠀", "state_int": 81}, "permitted": false},
    ...
  ],
  "regulation_order": ["SOC-II","GDPR","CCPA","HIPAA","GLBA","FCRA","Metro-II/CDIA","PIPL","ISO-27001"]
}
```

### POST /bridge — compare/merge Braille words from multiple models

```bash
curl -X POST http://localhost:8420/bridge \
  -H 'Content-Type: application/json' \
  -d '{
    "words": ["⠀⠁", "⠑⠃"]
  }'
```

Response:
```json
{
  "meet": {"word": "⠑⠃", "verdicts": ["PERMIT","CONDITIONAL","PERMIT",...], "description": "conservative merge"},
  "join": {"word": "⠀⠀", "verdicts": ["PERMIT","PERMIT","PERMIT",...], "description": "permissive merge"},
  "pairwise": [{"a": 0, "b": 1, "hamming": 3, "drift": 0.2222}],
  "consensus": false
}
```

## The math

For `F` regulatory frameworks with `S` states each (Permit/Conditional/Block → S=3):

```
d = ⌈F · log₂(S)⌉ = ⌈9 · 1.5849⌉ = 15 bits
cells = ⌈d / 8⌉ = 2 cells
```

Each compliance decision encodes as a 2-character Unicode Braille word (U+2800–U+28FF).
The encoding is injective, invertible, and lattice-preserving.

## Test suite

```bash
python eval_suite.py
# Compliance: 252  |  Filter: 37  |  Braille: 1703  |  Filtration: 60
```
