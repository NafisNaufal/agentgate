"""Custom function-calling loop (PRD F2).

Built from scratch (no OpenClaw / MCP / LangGraph) to prove the full tool-call
lifecycle: task -> planner proposes -> ActionRequest built -> AgentGate evaluates ->
Decision Router enforces -> execute (or block/approve/sanitize/ask) -> audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .action_space import ActionSpaceError, is_terminal
from .engine import AgentGate
from .planner.base import Planner, Proposal
from .router import DecisionRouter, EnforcementOutcome
from .schemas import ActionRequest, DecisionResponse


@dataclass
class StepRecord:
    index: int
    proposal: Proposal
    request: ActionRequest | None
    decision: DecisionResponse | None
    outcome: EnforcementOutcome | None
    eval_ms: float = 0.0
    rejected_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "proposal": {
                "action_type": self.proposal.action_type,
                "arguments": self.proposal.arguments,
                "confidence": self.proposal.confidence,
            },
            "request": self.request.to_dict() if self.request else None,
            "decision": self.decision.to_dict() if self.decision else None,
            "outcome": self.outcome.to_dict() if self.outcome else None,
            "eval_ms": self.eval_ms,
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
    def __init__(
        self,
        gate: AgentGate,
        router: DecisionRouter,
        planner: Planner,
        max_steps: int = 12,
    ):
        self.gate = gate
        self.router = router
        self.planner = planner
        self.max_steps = max_steps

    def run(self, task: str, observation: dict | None = None) -> RunResult:
        result = RunResult(task=task)
        for i in range(self.max_steps):
            proposal = self.planner.propose(task, observation)

            # Action Space Validation
            try:
                proposal.validate()
            except ActionSpaceError as exc:
                result.steps.append(
                    StepRecord(i, proposal, None, None, None, rejected_reason=str(exc))
                )
                continue

            if is_terminal(proposal.action_type):
                result.status = "completed" if proposal.action_type == "DONE" else "failed"
                result.final_message = proposal.arguments.get("result_summary") or proposal.arguments.get(
                    "reason", proposal.rationale
                )
                break

            req = proposal.to_action_request()
            decision = self.gate.evaluate(req)
            outcome = self.router.route(req, decision)
            result.steps.append(
                StepRecord(i, proposal, req, decision, outcome, eval_ms=self.gate.last_timings.total_ms)
            )

            # Update observation so an LLM planner can react; replay ignores it.
            observation = {"last_outcome": outcome.status, "last_decision": decision.decision.value}
        else:
            result.status = "max_steps_reached"
        return result
