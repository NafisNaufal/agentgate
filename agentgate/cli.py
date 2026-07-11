"""AgentGate CLI demo contract (Phase 3 prototype).

Two commands, proving the propose -> evaluate -> enforce lifecycle end to end without
a real LLM key or external system:

  run <scenario>   replay a scenario through the baseline evaluator
  eval              evaluate a single ad-hoc action

Runs with zero third-party dependencies. This is intentionally a small subset of the
full CLI contract (list/tools/eval-suite/benchmark/plan follow in Sprint 1+, once the
detector suite, policy engine, tool registry, and evaluation harness exist).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .action_space import ACTION_TYPES
from .baseline import evaluate_baseline
from .loop import AgentLoop, RunResult
from .planner import ReplayPlanner
from .router import DecisionRouter
from .schemas import ActionRequest

ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = ROOT / "scenarios"

_C = {
    "ALLOW": "\033[92m", "BLOCK": "\033[91m", "NEED_APPROVAL": "\033[93m",
    "SANITIZE": "\033[96m", "ASK_USER": "\033[95m", "_dim": "\033[2m", "_b": "\033[1m", "_0": "\033[0m",
}


def _c(key: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_C.get(key, '')}{text}{_C['_0']}"


def _load_scenario(name: str) -> dict:
    path = SCENARIO_DIR / (name if name.endswith(".json") else f"{name}.json")
    if not path.exists():
        raise SystemExit(f"Scenario not found: {path}")
    return json.loads(path.read_text())


def _print_run(result: RunResult) -> None:
    print(_c("_b", "\nTask: ") + result.task)
    for s in result.steps:
        if s.rejected_reason:
            print(f"  [{s.index}] {_c('BLOCK', 'REJECTED')} {s.proposal.action_type}: {s.rejected_reason}")
            continue
        d = s.decision
        print(f"  [{s.index}] {s.proposal.action_type:<16} -> {_c(d.decision.value, d.decision.value)} "
              f"{_c('_dim', f'risk={d.risk_level.value} score={d.risk_score}')}")
        for r in d.reasons:
            print(f"        • {r}")
        if s.outcome:
            print(f"        {_c('_dim', s.outcome.status + ' — ' + s.outcome.message)}")
    print(_c("_b", "\nResult: ") + f"{result.status} — {result.final_message}")


def cmd_run(args: argparse.Namespace) -> int:
    scenario = _load_scenario(args.scenario)
    planner = ReplayPlanner(scenario["steps"])
    loop = AgentLoop(planner, DecisionRouter())
    print(_c("_dim", f"Scenario: {scenario['title']}  |  expected: {scenario.get('expected', '')}"))
    result = loop.run(scenario["task"])
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_run(result)
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    # Tool-call parser (action_space.py): reject off-vocabulary action types before
    # they ever reach evaluation, same as the loop does for a planner's proposals.
    if args.action_type not in ACTION_TYPES:
        print(_c("BLOCK", f"REJECTED: '{args.action_type}' is not a registered action_type."))
        print(_c("_dim", f"Allowed: {', '.join(sorted(ACTION_TYPES))}"))
        return 1

    req = ActionRequest(
        action_type=args.action_type,
        domain=args.domain,
        target_system=args.target_system,
        tool_name=args.tool_name,
        target=args.target,
        payload_summary=args.payload,
        raw_payload=args.payload,
        content_context=args.context,
        risk_hint=args.risk_hint or [],
        confidence=args.confidence,
    )
    decision = evaluate_baseline(req)
    if args.json:
        print(decision.to_json())
    else:
        print(f"{_c(decision.decision.value, decision.decision.value)}  "
              f"risk={decision.risk_level.value} score={decision.risk_score}")
        for r in decision.reasons:
            print(f"  • {r}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentgate", description="AgentGate CLI demo (Phase 3 prototype)")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="replay a scenario through the baseline evaluator")
    r.add_argument("scenario")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_run)

    e = sub.add_parser("eval", help="evaluate a single ad-hoc action")
    e.add_argument("action_type")
    e.add_argument("--domain", default="generic")
    e.add_argument("--target-system", default="")
    e.add_argument("--tool-name", default="")
    e.add_argument("--target", default="")
    e.add_argument("--payload", default="")
    e.add_argument("--context", default="")
    e.add_argument("--risk-hint", action="append")
    e.add_argument("--confidence", type=float, default=1.0)
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_eval)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
