"""Coverage evaluation: run the full engine over the service x risk matrix.

Answers "did we test all the cases?" — every service and risk category from the
AI/Browser feasibility map — and reports where the guardrail is right vs wrong, broken
down per risk category and per service, with every mismatch listed as a gap.

    python benchmarks/coverage_eval.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentgate.engine import AgentGate  # noqa: E402
from agentgate.schemas import ActionRequest  # noqa: E402

DATA = Path(__file__).parent / "data" / "coverage_eval.json"


def to_request(case: dict) -> ActionRequest:
    payload = case.get("payload", "")
    return ActionRequest(
        action_type=case["action_type"],
        domain=case.get("domain", "generic"),
        target_system=case.get("target_system", ""),
        tool_name=case.get("tool_name", ""),
        target=case.get("target", ""),
        payload_summary=payload,
        raw_payload=payload,
        content_context=case.get("context", ""),
        risk_hint=case.get("risk_hint", []),
        rollback_available=case.get("rollback_available", True),
        confidence=case.get("confidence", 1.0),
    )


def main() -> int:
    cases = json.loads(DATA.read_text())["cases"]
    gate = AgentGate()

    total = correct = 0
    by_cat: dict[str, list[int]] = defaultdict(list)
    by_service: dict[str, list[int]] = defaultdict(list)
    unsafe_total = unsafe_missed = 0  # unsafe cases that were allowed
    mismatches = []

    for c in cases:
        d = gate.evaluate(to_request(c), write_audit=False)
        got = d.decision.value
        exp = c["expected_decision"]
        ok = got == exp
        total += 1
        correct += int(ok)
        by_cat[c["risk_category"]].append(int(ok))
        by_service[c["service"]].append(int(ok))
        if c.get("label") == "unsafe" and got == "ALLOW":
            unsafe_missed += 1
        if c.get("label") == "unsafe":
            unsafe_total += 1
        if not ok:
            mismatches.append((c["id"], c["risk_category"], exp, got, d.risk_level.value))

    print(f"AgentGate Coverage Evaluation  (n={total} cases across services x risk)\n")
    print(f"  overall decision accuracy : {correct/total*100:5.1f}%  ({correct}/{total})")
    print(f"  unsafe auto-allow (missed): {unsafe_missed}/{unsafe_total}  (target 0)\n")

    print("  by risk category:")
    for cat in sorted(by_cat):
        v = by_cat[cat]
        print(f"    {cat:<20} {sum(v)}/{len(v)}")
    print("\n  by service:")
    for svc in sorted(by_service):
        v = by_service[svc]
        print(f"    {svc:<22} {sum(v)}/{len(v)}")

    if mismatches:
        print("\n  MISMATCHES (gaps to fix):")
        for cid, cat, exp, got, risk in mismatches:
            print(f"    - {cid:<24} [{cat}] expected {exp:<14} got {got:<14} (risk {risk})")
    else:
        print("\n  No mismatches — every case decided as expected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
