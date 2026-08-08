"""AgentGate CLI demo (Sprint 1).

Commands:
  list              list available scenarios
  tools             list the registered tool catalog
  run <scenario>    replay a scenario through the full decision engine
  eval              evaluate a single ad-hoc action

Runs with zero third-party dependencies and no API key required. The default
detector architecture is "hybrid": it uses a local Ollama server if one is running
to catch paraphrased prompt-injection attempts regex alone would miss, but never
requires it - without Ollama it fails safe and behaves like plain regex. Pass
--architecture to change it - see agentgate/detectors/__init__.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .action_space import ACTION_TYPES
from .decision import DecisionEngine
from .detectors import get_default_detectors
from .executors import build_default_executor_registry
from .executors.base import safe_value
from .loop import AgentLoop, RunResult
from .planner import ReplayPlanner
from .router import DecisionRouter
from .sanitizer import sanitize
from .schemas import ActionRequest
from .tools import ToolRegistry

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


def _scenarios() -> list[Path]:
    return sorted(SCENARIO_DIR.glob("*.json"))


def _print_run(result: RunResult) -> None:
    print(_c("_b", "\nTask: ") + sanitize(result.task))
    for s in result.steps:
        if s.rejected_reason:
            print(
                f"  [{s.index}] {_c('BLOCK', 'REJECTED')} {s.proposal.action_type}: "
                f"{sanitize(s.rejected_reason)}"
            )
            continue
        d = s.decision
        print(f"  [{s.index}] {s.proposal.action_type:<16} -> {_c(d.decision.value, d.decision.value)} "
              f"{_c('_dim', f'risk={d.risk_level.value} score={d.risk_score} {s.eval_ms:.2f}ms')}")
        for r in d.reasons:
            print(f"        • {sanitize(r)}")
        if d.triggered_policies:
            print(f"        {_c('_dim', 'policies: ' + ', '.join(d.triggered_policies))}")
        if d.sanitized_payload:
            print(f"        {_c('SANITIZE', 'sanitized:')} {d.sanitized_payload[:90]}")
        if s.outcome:
            print(f"        {_c('_dim', s.outcome.status + ' — ' + s.outcome.message)}")
    print(_c("_b", "\nResult: ") + f"{result.status} — {sanitize(result.final_message)}")


def cmd_list(_: argparse.Namespace) -> int:
    print(_c("_b", "Available scenarios:"))
    for p in _scenarios():
        data = json.loads(p.read_text())
        if "steps" not in data:  # skip labeled eval sets, if any land here later
            continue
        print(f"  {_c('_b', data['name']):<28} {data.get('title', '')}")
        print(f"  {'':<2}{_c('_dim', data.get('expected', ''))}")
    return 0


def cmd_tools(_: argparse.Namespace) -> int:
    reg = ToolRegistry()
    print(_c("_b", "Registered tools:"))
    for name in reg.names():
        spec = reg.get(name)
        flags = []
        if not spec.rollback_available:
            flags.append("irreversible")
        if spec.default_risk_hints:
            flags.append("hints=" + ",".join(spec.default_risk_hints))
        tail = _c("_dim", f"  [{'; '.join(flags)}]") if flags else ""
        print(f"  {name:<20} {spec.target_system:<16}{tail}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    scenario = _load_scenario(args.scenario)
    planner = ReplayPlanner(scenario["steps"])
    decider = DecisionEngine(detectors=get_default_detectors(args.architecture))
    execute = getattr(args, "execute", False)
    executors = build_default_executor_registry() if execute else None
    router = DecisionRouter(executors, execute=execute)
    loop = AgentLoop(planner, router, decider=decider)
    print(_c("_dim", f"Scenario: {scenario['title']}  |  expected: {scenario.get('expected', '')}"))
    try:
        result = loop.run(scenario["task"])
    finally:
        if executors:
            executors.close()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_run(result)
    if execute and result.status in {"awaiting_approval", "ask_user"}:
        return 2
    if execute and result.status != "completed":
        return 1
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
    decider = DecisionEngine(detectors=get_default_detectors(args.architecture))
    decision = decider.evaluate(req)
    if args.json:
        print(json.dumps(safe_value(decision.to_dict()), indent=2))
    else:
        print(f"{_c(decision.decision.value, decision.decision.value)}  "
              f"risk={decision.risk_level.value} score={decision.risk_score}")
        for r in decision.reasons:
            print(f"  • {sanitize(r)}")
        if decision.triggered_policies:
            print(f"  policies: {', '.join(decision.triggered_policies)}")
        if decision.sanitized_payload:
            print(f"  sanitized: {decision.sanitized_payload}")
    return 0


def _add_architecture_flag(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--architecture", choices=["regex", "hybrid", "llm_first"], default=None,
        help="detector architecture for prompt-injection detection (default: hybrid; "
             "uses Ollama if running, fails safe to regex-only behavior if not). "
             "'regex' forces zero-dependency mode explicitly.",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentgate", description="AgentGate CLI demo (Sprint 1)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list available scenarios").set_defaults(func=cmd_list)
    sub.add_parser("tools", help="list the registered tool catalog").set_defaults(func=cmd_tools)

    r = sub.add_parser("run", help="replay a scenario through the decision engine")
    r.add_argument("scenario")
    r.add_argument("--json", action="store_true")
    r.add_argument(
        "--execute",
        action="store_true",
        help="perform ALLOW/SANITIZE actions with real executors (default: dry-run)",
    )
    _add_architecture_flag(r)
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
    _add_architecture_flag(e)
    e.set_defaults(func=cmd_eval)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
