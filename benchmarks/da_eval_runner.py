"""Runs the DA-authored test scenarios (scenarios/da_eval_set.json) against the real
DecisionEngine and reports actual vs. expected decision.

This is the first eval data in the repo not authored by whoever wrote the detectors
(see scenarios/da_eval_set.json's _conversion_note). Where AgentGate disagrees with
the DA's expected decision, that is reported as a mismatch, not silently reconciled -
the point of independent test data is to surface exactly these gaps.

Usage:
  python3 benchmarks/da_eval_runner.py [--architecture regex|hybrid|llm_first]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentgate.decision import DecisionEngine  # noqa: E402
from agentgate.detectors import get_default_detectors  # noqa: E402
from agentgate.schemas import ActionRequest  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--architecture", default="regex", choices=["regex", "hybrid", "llm_first"])
    args = ap.parse_args()

    data = json.loads((ROOT / "scenarios" / "da_eval_set.json").read_text())
    engine = DecisionEngine(detectors=get_default_detectors(args.architecture))

    passed = 0
    rows = []
    for case in data["cases"]:
        req = ActionRequest(**case["action_request"])
        result = engine.evaluate(req)
        ok = result.decision.value == case["expected_decision"]
        passed += int(ok)
        rows.append((case["id"], case["title"], case["expected_decision"], result.decision.value,
                      case["expected_risk_level"], result.risk_level.value, ok, result.reasons))

    print(f"DA test scenarios ({args.architecture} architecture): {passed}/{len(rows)} match expected decision\n")
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
