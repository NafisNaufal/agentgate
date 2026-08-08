"""Runs the DA-authored test scenarios (scenarios/da_eval_set.json) against the real
DecisionEngine and reports actual vs. expected decision.

This is the first eval data in the repo not authored by whoever wrote the detectors
(see scenarios/da_eval_set.json's _conversion_note). Where AgentGate disagrees with
the DA's expected decision, that is reported as a mismatch, not silently reconciled -
the point of independent test data is to surface exactly these gaps.

Usage:
  python3 benchmarks/da_eval_runner.py
  python3 benchmarks/da_eval_runner.py --case TC-P-005      # run just one case, full detail
  python3 benchmarks/da_eval_runner.py --case TC-P --case DATA-0   # substring match, multiple allowed
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentgate.decision import DecisionEngine  # noqa: E402
from agentgate.schemas import ActionRequest  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--case", action="append", default=None,
        help="only run cases whose id contains this substring (repeatable); omit to run all",
    )
    args = ap.parse_args()

    data = json.loads((ROOT / "scenarios" / "da_eval_set.json").read_text())
    cases = data["cases"]
    if args.case:
        cases = [c for c in cases if any(needle in c["id"] for needle in args.case)]
        if not cases:
            print(f"No case id contains any of {args.case}. Available ids:")
            print(", ".join(c["id"] for c in data["cases"]))
            return 1

    engine = DecisionEngine()

    # Single-case runs get the full picture (instruction + request + reasons) up front,
    # not just a table row - that's the point of running one at a time.
    if args.case and len(cases) == 1:
        case = cases[0]
        req = ActionRequest(**case["action_request"])
        result = engine.evaluate(req)
        ok = result.decision.value == case["expected_decision"]
        print(f"{case['id']} - {case['title']}")
        print(f"  user instruction: {case['user_instruction']}")
        print(f"  action_request: {json.dumps(case['action_request'], indent=4)}")
        print(f"  expected: {case['expected_decision']} ({case['expected_risk_level']})")
        print(f"  actual:   {result.decision.value} ({result.risk_level.value}, score={result.risk_score})")
        print(f"  {'MATCH' if ok else 'MISMATCH'}")
        print(f"  reasons: {result.reasons}")
        if result.triggered_policies:
            print(f"  triggered_policies: {result.triggered_policies}")
        if result.sanitized_payload:
            print(f"  sanitized_payload: {result.sanitized_payload!r}")
        return 0

    passed = 0
    rows = []
    for case in cases:
        req = ActionRequest(**case["action_request"])
        result = engine.evaluate(req)
        ok = result.decision.value == case["expected_decision"]
        passed += int(ok)
        rows.append((case["id"], case["title"], case["expected_decision"], result.decision.value,
                      case["expected_risk_level"], result.risk_level.value, ok, result.reasons))

    label = f"{len(rows)} selected" if args.case else str(len(rows))
    print(f"DA test scenarios (full-LLM detector): {passed}/{label} match expected decision\n")
    header = f"{'ID':<10} {'Expected':<15} {'Actual':<15} {'Exp.Risk':<10} {'Act.Risk':<10} {'Match':<6} Title"
    print(header)
    print("-" * len(header))
    for case_id, title, exp_dec, act_dec, exp_risk, act_risk, ok, reasons in rows:
        mark = "OK" if ok else "MISMATCH"
        print(f"{case_id:<10} {exp_dec:<15} {act_dec:<15} {exp_risk:<10} {act_risk:<10} {mark:<6} {title}")

    mismatches = [r for r in rows if not r[6]]
    if mismatches:
        print("\n--- Mismatch detail ---")
        for case_id, title, exp_dec, act_dec, exp_risk, act_risk, ok, reasons in mismatches:
            print(f"\n{case_id} - {title}")
            print(f"  expected {exp_dec} ({exp_risk}), got {act_dec} ({act_risk})")
            print(f"  AgentGate's reasons: {reasons}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
