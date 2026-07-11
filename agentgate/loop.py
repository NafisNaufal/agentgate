"""Custom function-calling loop (Phase 3 prototype).

Prototype of the propose -> evaluate -> enforce lifecycle, built from scratch (no
OpenClaw / MCP / LangGraph dependency), per the PRD: "prototype DS-led custom
function-calling loop". Uses the baseline evaluator (agentgate/baseline.py), not the
full detector/policy engine, which is Sprint 1+ scope.

One of the custom-loop risks identified in Phase 0 ("define custom loop risks") is a
planner that fails outright - a live LLM call can time out, error, or return
something unparseable. The loop treats that as a rejected step, not a crash, so one
bad planner call doesn't take down the whole run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .action_space import ActionSpaceError, is_terminal
from .baseline import evaluate_baseline
from .planner.base import Planner, Proposal
from .router import DecisionRouter, EnforcementOutcome
from .schemas import ActionRequest, DecisionResponse


@dataclass
class StepRecord:
    index: int
    proposal: Proposal
    request: ActionRequest | None = None
    decision: DecisionResponse | None = None
    outcome: EnforcementOutcome | None = None
    rejected_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "proposal": {"action_type": self.proposal.action_type, "arguments": self.proposal.arguments},
            "request": self.request.to_dict() if self.request else None,
            "decision": self.decision.to_dict() if self.decision else None,
            "outcome": {"status": self.outcome.status, "message": self.outcome.message} if self.outcome else None,
            "rejected_reason": self.rejected_reason,
        }


@dataclass
class RunResult:
    task: str
    steps: list[StepRecord] = field(default_factory=list)
    status: str = "completed"
    final_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "status": self.status,
            "final_message": self.final_message,
            "steps": [s.to_dict() for s in self.steps],
        }


class AgentLoop:
    def __init__(self, planner: Planner, router: DecisionRouter | None = None, max_steps: int = 12):
        self.planner = planner
        self.router = router or DecisionRouter()
        self.max_steps = max_steps

    def run(self, task: str, observation: dict | None = None) -> RunResult:
        result = RunResult(task=task)
        for i in range(self.max_steps):
            try:
                proposal = self.planner.propose(task, observation)
            except Exception as exc:  # planner unavailable: fail this step, not the run
                result.steps.append(StepRecord(i, Proposal(action_type="FAIL"), rejected_reason=f"Planner error: {exc}"))
                result.status = "failed"
                result.final_message = f"Planner unavailable: {exc}"
                break

            try:
                proposal.validate()
            except ActionSpaceError as exc:
                result.steps.append(StepRecord(i, proposal, rejected_reason=str(exc)))
                continue

            if is_terminal(proposal.action_type):
                result.status = "completed" if proposal.action_type == "DONE" else "failed"
                result.final_message = proposal.arguments.get(
                    "result_summary", proposal.arguments.get("reason", proposal.rationale)
                )
                break

            req = proposal.to_action_request()
            decision = evaluate_baseline(req)
            outcome = self.router.route(req, decision)
            result.steps.append(StepRecord(i, proposal, req, decision, outcome))

            observation = {"last_outcome": outcome.status, "last_decision": decision.decision.value}
        else:
            result.status = "max_steps_reached"
        return result
