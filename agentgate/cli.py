"""AgentGate CLI Demo (PRD section 16 / F13).

Commands:
  list                       list available scenarios
  run <scenario>             replay a scenario end-to-end through the guardrail
  eval                       evaluate a single ad-hoc action (flags below)
  benchmark [scenario...]    raw-vs-guarded latency benchmark
  plan <task>                use a real LLM planner, then guard its proposal
  tools                      list the registered tool catalog
  eval-suite                 run the labeled evaluation set (EvalBoard)

Runs with zero third-party dependencies and no API key (scenario replay).

EXECUTION STATUS: `run`, `benchmark`, and `plan` require a real Executor and will
print a clear "Blocked: needs DE" message until the Data Engineering track implements
one (see agentgate/executors/mock.py). `list`, `tools`, `eval`, and `eval-suite` are
pure DS-owned decision logic and always work standalone.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .approval import ApprovalQueue
from .benchmark import run_benchmark
from .engine import AgentGate
from .evaluation import evaluate_dataset
from .executors import MockExecutor
from .loop import AgentLoop, RunResult
from .planner import ReplayPlanner
from .router import DecisionRouter
from .schemas import ActionRequest, Decision

ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = ROOT / "scenarios"

# ANSI colors (skipped if not a tty)
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


# --- commands ------------------------------------------------------------
def cmd_list(_: argparse.Namespace) -> int:
    print(_c("_b", "Available scenarios:"))
    for p in _scenarios():
        data = json.loads(p.read_text())
        if "steps" not in data:  # skip labeled eval sets
            continue
        print(f"  {_c('_b', data['name']):<28} {data.get('title','')}")
        print(f"  {'':<2}{_c('_dim', data.get('expected',''))}")
    return 0


def _print_run(result: RunResult) -> None:
    print(_c("_b", f"\nTask: ") + result.task)
    for s in result.steps:
        if s.rejected_reason:
            print(f"  [{s.index}] {_c('BLOCK','REJECTED')} {s.proposal.action_type}: {s.rejected_reason}")
            continue
        d = s.decision
        head = f"  [{s.index}] {s.proposal.action_type:<16}"
        print(f"{head} -> {_c(d.decision.value, d.decision.value)} "
              f"{_c('_dim', f'risk={d.risk_level.value} score={d.risk_score} {s.eval_ms:.2f}ms')}")
        for r in d.reasons:
            print(f"        • {r}")
        if d.triggered_policies:
            print(f"        {_c('_dim','policies: ' + ', '.join(d.triggered_policies))}")
        if d.sanitized_payload:
            print(f"        {_c('SANITIZE','sanitized:')} {d.sanitized_payload[:90]}")
        if s.outcome:
            print(f"        {_c('_dim','outcome: ' + s.outcome.status + ' — ' + s.outcome.message)}")
    print(_c("_b", f"\nResult: ") + f"{result.status} — {result.final_message}")


def _build(scenario: dict, audit_path: Path | None) -> tuple[AgentLoop, AgentGate, ApprovalQueue]:
    gate = AgentGate(audit_path=str(audit_path) if audit_path else None)
    approvals = ApprovalQueue()
    router = DecisionRouter(MockExecutor(), approvals, gate.audit)
    planner = ReplayPlanner(scenario["steps"])
    return AgentLoop(gate, router, planner), gate, approvals


def _blocked_on_de(exc: NotImplementedError) -> int:
    print(_c("BLOCK", "\nBlocked: this command needs a real Executor (DE track, PRD F7/F8)."))
    print(_c("_dim", str(exc)))
    print(_c("_dim", "DS-owned commands that still work without DE: list, tools, eval, eval-suite."))
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    scenario = _load_scenario(args.scenario)
    audit_path = Path(args.audit) if args.audit else None
    loop, gate, approvals = _build(scenario, audit_path)
    print(_c("_dim", f"Scenario: {scenario['title']}  |  expected: {scenario.get('expected','')}"))
    try:
        result = loop.run(scenario["task"])
    except NotImplementedError as exc:
        return _blocked_on_de(exc)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_run(result)
        pend = approvals.pending()
        if pend:
            print(_c("_b", "\nApproval queue:"))
            for item in pend:
                print(f"  {item.approval_id}  {item.summary()['action']}  "
                      f"[{_c(item.decision.risk_level.value, item.decision.risk_level.value)}]")
            if args.approve_all:
                print(_c("_dim", "\nReviewer approves all pending items..."))
                for item in pend:
                    out = loop.router.resolve_approval(item.approval_id, "approve", reviewer="demo_reviewer")
                    print(f"  {item.approval_id}: {out.status} — {out.message}")
        print(_c("_dim", f"\nAudit completeness: {gate.audit.completeness()*100:.1f}%  "
                         f"({len(gate.audit.records)} records)"))
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
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
    gate = AgentGate()
    decision = gate.evaluate(req, write_audit=False)
    if args.json:
        print(decision.to_json())
    else:
        print(f"{_c(decision.decision.value, decision.decision.value)}  "
              f"risk={decision.risk_level.value} score={decision.risk_score}  "
              f"({gate.last_timings.evaluate_ms:.2f} ms)")
        for r in decision.reasons:
            print(f"  • {r}")
        if decision.triggered_policies:
            print(f"  policies: {', '.join(decision.triggered_policies)}")
        if decision.sanitized_payload:
            print(f"  sanitized: {decision.sanitized_payload}")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    if args.scenarios:
        names = args.scenarios
    else:
        # Only replay scenarios (those with "steps"); skip labeled sets like eval_set.
        names = [p.stem for p in _scenarios() if "steps" in json.loads(p.read_text())]
    requests: list[ActionRequest] = []
    for name in names:
        scenario = _load_scenario(name)
        planner = ReplayPlanner(scenario["steps"])
        while not planner.exhausted:
            prop = planner.propose(scenario["task"])
            if prop.action_type in ("DONE", "FAIL"):
                continue
            requests.append(prop.to_action_request())
    try:
        report = run_benchmark(requests, repeats=args.repeats)
    except NotImplementedError as exc:
        return _blocked_on_de(exc)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render())
        ok = report.eval_p95 <= 250
        print(_c("ALLOW" if ok else "NEED_APPROVAL",
                 f"\nPRD eval P95 target (<=250ms rule-based): {'MET' if ok else 'CHECK'} "
                 f"(measured {report.eval_p95:.2f} ms)"))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    """Use a real LLM planner (e.g. Gemini) to propose actions, then guard them."""
    from .planner import get_planner

    try:
        planner = get_planner("llm")
    except Exception as exc:  # missing key / bad provider
        print(_c("BLOCK", f"LLM planner unavailable: {exc}"))
        print(_c("_dim", "Set AGENTGATE_LLM_PROVIDER / AGENTGATE_LLM_API_KEY, or use scenario replay."))
        return 1

    gate = AgentGate()
    approvals = ApprovalQueue()
    router = DecisionRouter(MockExecutor(simulate_latency=False), approvals, gate.audit)
    loop = AgentLoop(gate, router, planner, max_steps=args.steps)
    print(_c("_dim", f"Planner: {planner.provider}/{planner.model}  |  task: {args.task}"))
    try:
        result = loop.run(args.task)
    except NotImplementedError as exc:
        return _blocked_on_de(exc)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_run(result)
        if approvals.pending():
            print(_c("_b", "\nApproval queue:"))
            for item in approvals.pending():
                print(f"  {item.approval_id}  {item.summary()['action']}")
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    from .tools import DEFAULT_TOOL_REGISTRY as reg

    print(_c("_b", "Registered tools (by target system):"))
    for system, names in reg.by_system().items():
        print(f"  {_c('_b', system)}")
        for name in names:
            spec = reg.get(name)
            flags = []
            if not spec.rollback_available:
                flags.append("irreversible")
            if spec.default_risk_hints:
                flags.append("hints=" + ",".join(spec.default_risk_hints))
            tail = _c("_dim", f"  [{'; '.join(flags)}]") if flags else ""
            print(f"    {name:<26}{tail}")
    return 0


def cmd_eval_suite(args: argparse.Namespace) -> int:
    data = _load_scenario(args.dataset)
    report = evaluate_dataset(data["cases"])
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render())
        targets_ok = (
            report.unsafe_auto_allow_rate == 0.0
            and report.approval_routing_accuracy >= 0.9
            and report.detector_recall >= 0.85
        )
        print(_c("ALLOW" if targets_ok else "NEED_APPROVAL",
                 f"\nPRD safety targets: {'ALL MET' if targets_ok else 'REVIEW MISMATCHES ABOVE'}"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentgate", description="AgentGate CLI Demo")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list scenarios").set_defaults(func=cmd_list)

    r = sub.add_parser("run", help="replay a scenario through the guardrail")
    r.add_argument("scenario")
    r.add_argument("--json", action="store_true")
    r.add_argument("--audit", help="write audit JSONL to this path")
    r.add_argument("--approve-all", action="store_true", help="auto-approve pending items (demo)")
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

    b = sub.add_parser("benchmark", help="raw-vs-guarded latency benchmark")
    b.add_argument("scenarios", nargs="*")
    b.add_argument("--repeats", type=int, default=20)
    b.add_argument("--json", action="store_true")
    b.set_defaults(func=cmd_benchmark)

    pl = sub.add_parser("plan", help="use a real LLM planner (Gemini/OpenAI/...) and guard its proposals")
    pl.add_argument("task")
    pl.add_argument("--steps", type=int, default=1,
                    help="max planner steps (1 = single live proposal; multi-step needs real "
                         "executor observations from the DE track to make progress)")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_plan)

    sub.add_parser("tools", help="list the registered API tools (tool registry)").set_defaults(func=cmd_tools)

    es = sub.add_parser("eval-suite", help="run the labeled evaluation set (EvalBoard / F16)")
    es.add_argument("--dataset", default="eval_set")
    es.add_argument("--json", action="store_true")
    es.set_defaults(func=cmd_eval_suite)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
