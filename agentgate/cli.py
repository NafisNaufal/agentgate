"""AgentGate CLI demo (Sprint 1).

Commands:
  list              list available scenarios
  tools             list the registered tool catalog
  run <scenario>    run a scenario through the full decision engine
  eval              evaluate a single ad-hoc action
  google-auth       run the Google OAuth consent flow for the Gmail executor
  serve             start the web Demo Console

The guardrail always uses the full local-LLM detector suite via Ollama. The planner
is a separate layer: it defaults to deterministic scenario replay, and ``run
--planner llm`` swaps in a live remote LLM planner without changing the guardrail.
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib.resources import files
from typing import Any

from .action_space import ACTION_TYPES
from .audit import AuditUnavailable
from .decision import DecisionEngine
from .executors import build_default_executor_registry
from .executors.base import safe_value
from .loop import AgentLoop, RunResult
from .planner import ReplayPlanner, get_planner
from .router import DecisionRouter
from .sanitizer import sanitize
from .schemas import ActionRequest
from .tools import ToolRegistry

SCENARIO_DIR = files("agentgate").joinpath("scenarios")

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


def _scenarios() -> list[Any]:
    return sorted(
        (path for path in SCENARIO_DIR.iterdir() if path.name.endswith(".json")),
        key=lambda path: path.name,
    )


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
            print(
                f"        {_c('_dim', s.outcome.status + ' — ' + sanitize(s.outcome.message))}"
            )
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


def _build_planner(scenario: dict, kind: str):
    """Replay the recorded steps, or let a real LLM plan the same task from scratch.

    The guardrail is planner-agnostic by design (PRD F2: "the model suggests,
    AgentGate validates"), so the same scenario task can be driven either way and
    must produce the same class of decisions.
    """
    if kind == "replay":
        return ReplayPlanner(scenario["steps"])
    try:
        return get_planner("llm")
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(
            f"LLM planner unavailable: {exc}\n"
            "Set AGENTGATE_LLM_PROVIDER and AGENTGATE_LLM_API_KEY, or use "
            "--planner replay (the default)."
        ) from exc


def cmd_run(args: argparse.Namespace) -> int:
    scenario = _load_scenario(args.scenario)
    planner = _build_planner(scenario, args.planner)
    decider = DecisionEngine()
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

    registry = ToolRegistry()
    spec = registry.get(args.tool_name) if args.action_type == "API_CALL" else None
    risk_hints = list(
        dict.fromkeys([*(args.risk_hint or []), *(spec.default_risk_hints if spec else ())])
    )
    req = ActionRequest(
        action_type=args.action_type,
        domain=args.domain,
        target_system=spec.target_system if spec else args.target_system,
        tool_name=args.tool_name,
        target=args.target,
        payload_summary=args.payload,
        raw_payload=args.payload,
        content_context=args.context,
        risk_hint=risk_hints,
        rollback_available=spec.rollback_available if spec else True,
        confidence=args.confidence,
    )
    decider = DecisionEngine()
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


def cmd_google_auth(_: argparse.Namespace) -> int:
    """Run the Gmail consent flow. Never executes an agent action."""
    from .executors.google_auth import AuthError, run_consent_flow

    try:
        path = run_consent_flow()
    except AuthError as exc:
        print(_c("BLOCK", f"Google authorization failed: {exc}"), file=sys.stderr)
        return 1
    print(f"Google token stored at {path} (mode 0600). It is gitignored.")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the Demo Console. Requires AGENTGATE_WEB_PASSWORD."""
    from .web.auth import AuthNotConfigured
    from .web.app import serve

    try:
        serve(host=args.host, port=args.port)
    except AuthNotConfigured as exc:
        print(_c("BLOCK", str(exc)), file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentgate", description="AgentGate CLI demo (Sprint 1)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list available scenarios").set_defaults(func=cmd_list)
    sub.add_parser("tools", help="list the registered tool catalog").set_defaults(func=cmd_tools)

    r = sub.add_parser("run", help="replay a scenario through the decision engine")
    r.add_argument("scenario")
    r.add_argument("--json", action="store_true")
    r.add_argument(
        "--planner",
        choices=("replay", "llm"),
        default="replay",
        help="replay the scenario's recorded steps (default), or plan live with an LLM",
    )
    r.add_argument(
        "--execute",
        action="store_true",
        help="perform ALLOW/SANITIZE actions with real executors (default: dry-run)",
    )
    r.set_defaults(func=cmd_run)

    sub.add_parser(
        "google-auth", help="run the Google OAuth consent flow for the Gmail executor"
    ).set_defaults(func=cmd_google_auth)

    w = sub.add_parser("serve", help="start the web Demo Console")
    w.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback only)")
    w.add_argument("--port", type=int, default=8080)
    w.set_defaults(func=cmd_serve)

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
    try:
        return args.func(args)
    except AuditUnavailable as exc:
        # Auditing is mandatory, so this is a hard stop - but the operator needs a
        # fix, not a traceback.
        print(_c("BLOCK", f"Audit store unavailable: {exc}"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
