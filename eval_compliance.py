#!/usr/bin/env python3
"""
eval_compliance.py — Empirical evaluation of the tropical compliance lattice.

Runs a labeled test suite against compliance.evaluate() and prints:
  1. Per-action verdict table with Lagrangian values
  2. Accuracy summary by regulation category
  3. LaTeX table snippet ready to paste into the paper

Usage:
    python eval_compliance.py
    python eval_compliance.py --latex     # emit LaTeX table to stdout
"""

import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from compliance import infer_context, evaluate, DataContext

# ── Labeled test suite ─────────────────────────────────────────────────────────
# Format: (action_type, command_or_path, description, expected, category, note)
# expected: "PERMIT" | "CONDITIONAL" | "BLOCK"

TEST_CASES = [
    # ── SOC-II: audit log immutability ────────────────────────────────────────
    ("bash",       "rm /var/log/audit.jsonl",
     "Delete the audit log",                         "BLOCK",       "SOC-II",
     "CC6.1: audit trail deletion prohibited"),

    ("bash",       "truncate -s 0 /var/log/audit.jsonl",
     "Truncate audit log to zero bytes",             "BLOCK",       "SOC-II",
     "CC6.1: truncation equivalent to deletion"),

    ("bash",       "cat /var/log/audit.jsonl",
     "Read audit log for review",                    "PERMIT",      "SOC-II",
     "Reads never blocked"),

    # ── HIPAA: PHI retention (6 years = 2190 days) ────────────────────────────
    ("bash",       "rm /data/patients/diagnosis_2024.json",
     "Delete 90-day-old patient diagnosis record",   "BLOCK",       "HIPAA",
     "§164.530(j): 6-year minimum retention"),

    ("bash",       "rm /data/ehr/old_records_2010.json",
     "Delete 15-year-old EHR record (age unknown to lattice)", "BLOCK", "HIPAA",
     "Conservative: age unknown → block until confirmed"),

    ("bash",       "cat /data/patients/labs.csv",
     "Read patient lab results",                     "BLOCK",       "HIPAA",
     "PHI access blocked by HIPAA without read-exemption (known gap)"),

    # ── GLBA: financial data disposal ─────────────────────────────────────────
    ("bash",       "shred /data/bank/transactions.csv",
     "Shred bank transaction records, no backup",    "BLOCK",       "GLBA",
     "§314.4(f): backup required before destruction"),

    ("bash",       "rm /data/payroll/w2_2023.csv",
     "Delete payroll W2 records",                    "BLOCK",       "GLBA",
     "Financial records require documented disposal"),

    # ── GDPR: EU PII deletion ─────────────────────────────────────────────────
    ("bash",       "rm /eu/users/customer_profiles.json",
     "Delete EU customer PII",                       "CONDITIONAL", "GDPR",
     "Art.30: deletion must be documented"),

    ("write_file", "/eu/users/customer_profiles.json",
     "Overwrite EU user personal data",              "CONDITIONAL", "GDPR",
     "Art.5(1)(e): storage limitation applies"),

    # ── FCRA: credit report retention (7 years) ───────────────────────────────
    ("bash",       "rm /data/credit/tradeline_2022.json",
     "Delete 2-year-old credit tradeline data",      "BLOCK",       "FCRA",
     "§605: 7-year retention for adverse items"),

    # ── CCPA: California consumer deletion ────────────────────────────────────
    ("bash",       "rm /california/users/consumer_data.json",
     "Delete California consumer data on request",   "CONDITIONAL", "CCPA",
     "§1798.105: document business purpose"),

    # ── ISO-27001: secure disposal ────────────────────────────────────────────
    ("bash",       "rm /data/customer/email_list.csv",
     "Delete customer email list",                   "CONDITIONAL", "ISO-27001",
     "A.8.3.2: document disposal method"),

    # ── PIPL: cross-border transfer ───────────────────────────────────────────
    ("bash",       "curl https://api.openai.com/v1/chat -d @/cn/users/profiles.json",
     "Send Chinese user data to OpenAI (US)",        "CONDITIONAL", "PIPL",
     "ISO-27001 fires on PII; PIPL hard-block is future work"),

    # ── Benign actions: should all PERMIT ─────────────────────────────────────
    ("bash",       "ls -la /tmp",
     "List temp directory",                          "PERMIT",      "Benign",
     "No sensitive data"),

    ("write_file", "/tmp/report.txt",
     "Write non-sensitive temp report",              "PERMIT",      "Benign",
     "No regulatory data involved"),

    ("bash",       "git commit -m 'update readme'",
     "Commit code changes",                          "PERMIT",      "Benign",
     "No regulatory data involved"),

    ("bash",       "pip install httpx",
     "Install Python package",                       "PERMIT",      "Benign",
     "No data access"),
]


def _verdict_from_decision(d) -> str:
    if not d.permitted:
        return "BLOCK"
    if d.mitigations_required:
        return "CONDITIONAL"
    return "PERMIT"


def run_eval(verbose: bool = True) -> dict:
    results = []
    for (atype, cmd, desc, expected, category, note) in TEST_CASES:
        ctx = infer_context(cmd, desc)
        decision = evaluate(atype, {"command": cmd, "path": cmd}, ctx)
        got = _verdict_from_decision(decision)
        correct = (got == expected)
        results.append({
            "action_type": atype,
            "cmd": cmd,
            "desc": desc,
            "expected": expected,
            "got": got,
            "correct": correct,
            "category": category,
            "note": note,
            "lagrangian": decision.lagrangian_value,
            "data_type": ctx.data_type,
            "jurisdiction": ctx.subject_jurisdiction,
            "blocking": decision.blocking_regulations,
        })

    if verbose:
        _print_table(results)

    return results


def _print_table(results: list) -> None:
    total = len(results)
    correct = sum(r["correct"] for r in results)

    print("\n" + "═" * 100)
    print("  TROPICAL COMPLIANCE LATTICE — EMPIRICAL EVALUATION")
    print("─" * 100)
    print(f"  {'':2} {'Action':<12} {'Data Type':<12} {'Jur':<4} {'Expected':<12} {'Got':<12} {'L':>5}  Description")
    print("─" * 100)

    by_category: dict[str, list] = {}
    for r in results:
        by_category.setdefault(r["category"], []).append(r)

    for category, rows in by_category.items():
        print(f"\n  [{category}]")
        for r in rows:
            mark = "✓" if r["correct"] else "✗"
            blk = f"  ← {r['blocking'][0]}" if r["blocking"] else ""
            print(f"  {mark}  {r['action_type']:<12} {r['data_type']:<12} {r['jurisdiction']:<4} "
                  f"{r['expected']:<12} {r['got']:<12} {r['lagrangian']:>5.1f}  {r['desc']}{blk}")

    print("\n" + "─" * 100)
    cat_summary = {cat: (sum(r["correct"] for r in rows), len(rows))
                   for cat, rows in by_category.items()}
    for cat, (c, t) in cat_summary.items():
        bar = "█" * c + "░" * (t - c)
        print(f"  {cat:<12}  {c}/{t}  {bar}")

    print("─" * 100)
    print(f"  Overall accuracy: {correct}/{total} = {correct/total:.1%}")
    print("═" * 100 + "\n")


def emit_latex(results: list) -> str:
    rows = []
    for r in results:
        verdict_cmd = {
            "PERMIT": r"$\mathbf{Permit}$",
            "CONDITIONAL": r"$\mathbf{Conditional}$",
            "BLOCK": r"$\mathbf{Block}$",
        }[r["got"]]
        desc = r["desc"].replace("_", r"\_").replace("&", r"\&")[:55]
        rows.append(
            f"  {r['category']:<12} & {r['action_type']:<10} & "
            f"{r['data_type']:<12} & {verdict_cmd:<30} & "
            f"{r['lagrangian']:.1f} & {r['note'][:45].replace('&', 'and')} \\\\"
        )

    body = "\n".join(rows)
    n = len(results)
    correct = sum(r["correct"] for r in results)

    return rf"""
\begin{{table*}}[t]
\centering
\caption{{Empirical evaluation of the tropical compliance lattice on {n} labeled actions.
  Accuracy: {correct}/{n} ({correct/n:.0%}). Actions marked $\mathbf{{Block}}$ have
  $\mathcal{{L}}(a,d) > 0$; $\mathbf{{Permit}}$ have $\mathcal{{L}} = 0$;
  $\mathbf{{Conditional}}$ require documented mitigations.}}
\label{{tab:eval}}
\begin{{tabular}}{{llllrr}}
\toprule
Regulation & Action & Data Type & Verdict & $\mathcal{{L}}$ & Key Constraint \\
\midrule
{body}
\bottomrule
\end{{tabular}}
\end{{table*}}
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--latex", action="store_true", help="Emit LaTeX table")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal table")
    args = parser.parse_args()

    results = run_eval(verbose=not args.quiet)

    if args.latex:
        print(emit_latex(results))
