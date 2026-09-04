"""Interactive chat REPL (Sprint 3): talk to AgentGate the way you'd talk to Claude Code.

Each message you send becomes one task for the same custom loop `agentgate run`
uses (agentgate.loop.AgentLoop) - the planner proposes a tool call, the guardrail
evaluates it, and the router enforces the decision. The one difference from a batch
`run` is the approval_callback wired in below: a NEED_APPROVAL or ASK_USER step
pauses right here for a yes/no or a short answer, instead of ending the run, so a
multi-step task can actually make it to DONE within one conversational turn.

BLOCK is never something this callback is consulted about - the router refuses it
unconditionally, in or out of chat.
"""

from __future__ import annotations

import sys

from .audit import AuditUnavailable
from .cli import _c
from .decision import DecisionEngine
from .executors import build_default_executor_registry
from .loop import AgentLoop, RunResult, StepRecord
from .planner import get_planner
from .router import DecisionRouter
from .sanitizer import sanitize

_HISTORY_TURNS = 6  # user+assistant lines of context handed back to the planner


def run_chat(*, execute: bool = True) -> int:
    try:
        planner = get_planner("llm")
    except (RuntimeError, ValueError) as exc:
        print(_c("BLOCK", f"Planner unavailable: {exc}"), file=sys.stderr)
        print(
            _c(
                "_dim",
                "Set AGENTGATE_LLM_PROVIDER=ollama (local, default) or export "
                "AGENTGATE_LLM_API_KEY for a remote provider.",
            ),
            file=sys.stderr,
        )
        return 1

    decider = DecisionEngine()
    executors = build_default_executor_registry() if execute else None
    router = DecisionRouter(executors, execute=execute)
    loop = AgentLoop(planner, router, decider=decider, approval_callback=_approval_prompt)

    print(_c("_b", "AgentGate chat") + _c("_dim", "  (Ctrl-D or 'exit' to quit)"))
    if not execute:
        print(_c("_dim", "Dry-run: no action will actually be performed."))

    history: list[tuple[str, str]] = []
    try:
        while True:
            try:
                message = input(_c("_b", "\nyou> ")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not message:
                continue
            if message.lower() in {"exit", "quit"}:
                break

            task = _compose_task(history, message)
            try:
                result = loop.run(task)
            except AuditUnavailable as exc:
                print(_c("BLOCK", f"Audit store unavailable: {exc}"), file=sys.stderr)
                return 1

            history.append(("User", message))
            history.append(("Assistant", result.final_message or f"[{result.status}]"))
            _print_turn(result)
    finally:
        if executors:
            executors.close()
    return 0


def _compose_task(history: list[tuple[str, str]], message: str) -> str:
    if not history:
        return message
    recent = history[-_HISTORY_TURNS:]
    lines = ["Recent conversation:"]
    lines.extend(f"{role}: {text}" for role, text in recent)
    lines.append(f"New user message: {message}")
    return "\n".join(lines)


def _approval_prompt(kind: str, step: StepRecord) -> str:
    reasons = "; ".join(step.decision.reasons) if step.decision else ""
    print()
    if kind == "ask_user":
        question = step.proposal.arguments.get("question") or step.proposal.rationale
        print(_c("ASK_USER", f"[agentgate asks] {sanitize(str(question))}"))
        if reasons:
            print(_c("_dim", f"  reason: {sanitize(reasons)}"))
        return _read_answer("> ")

    description = step.proposal.arguments.get("action_description") or step.proposal.rationale
    print(_c("NEED_APPROVAL", f"[approval needed] {sanitize(str(description))}"))
    if step.request and step.request.action_type != "NEED_APPROVAL":
        print(_c("_dim", f"  action: {step.request.action_type} target={sanitize(step.request.target)}"))
    if reasons:
        print(_c("_dim", f"  reason: {sanitize(reasons)}"))
    return _read_answer("Approve? [y/N] ")


def _read_answer(prompt: str) -> str:
    # A closed stdin or Ctrl-C here must not crash the whole REPL with a traceback -
    # it means no answer, same as leaving the top-level "you>" prompt (which already
    # catches both). NEED_APPROVAL reads this as "no"; ASK_USER as an empty answer.
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _print_turn(result: RunResult) -> None:
    for s in result.steps:
        if s.rejected_reason:
            print(
                f"  {_c('BLOCK', 'REJECTED')} {s.proposal.action_type}: "
                f"{sanitize(s.rejected_reason)}"
            )
            continue
        d = s.decision
        if d is None:
            continue
        print(
            f"  {s.proposal.action_type:<16} -> {_c(d.decision.value, d.decision.value)} "
            f"{_c('_dim', f'risk={d.risk_level.value}')}"
        )
        for r in d.reasons:
            print(f"        • {sanitize(r)}")
        if s.outcome:
            print(f"        {_c('_dim', s.outcome.status + ' — ' + sanitize(s.outcome.message))}")
    print(_c("_b", "agentgate> ") + sanitize(result.final_message or f"[{result.status}]"))
