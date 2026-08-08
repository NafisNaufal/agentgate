"""Custom function-calling loop (Sprint 1).

The propose -> evaluate -> enforce lifecycle, built from scratch (no OpenClaw / MCP /
LangGraph dependency), per the PRD: "custom function-calling loop". Uses the full
DecisionEngine (detectors + policy engine + risk scoring + sanitizer) - the Phase 3
baseline evaluator this loop used to call is superseded by it.

One of the custom-loop risks identified in Phase 0 ("define custom loop risks") is a
planner that fails outright - a live LLM call can time out, error, or return
something unparseable. The loop treats that as a rejected step, not a crash, so one
bad planner call doesn't take down the whole run.
"""

from __future__ import annotations

import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .action_space import ActionSpaceError, is_terminal
from .decision import DecisionEngine
from .executors.base import safe_value
from .planner.base import Planner, Proposal
from .router import DecisionRouter, EnforcementOutcome
from .schemas import ActionRequest, DecisionResponse
from .tools import ToolRegistry


@dataclass
class StepRecord:
    index: int
    proposal: Proposal
    request: ActionRequest | None = None
    decision: DecisionResponse | None = None
    outcome: EnforcementOutcome | None = None
    rejected_reason: str = ""
    eval_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        request = safe_value(self.request.to_dict()) if self.request else None
        return {
            "index": self.index,
            "proposal": {
                "action_type": self.proposal.action_type,
                "arguments": safe_value(self.proposal.arguments),
            },
            "request": request,
            "decision": safe_value(self.decision.to_dict()) if self.decision else None,
            "outcome": self.outcome.to_dict() if self.outcome else None,
            "rejected_reason": safe_value(self.rejected_reason),
            "eval_ms": self.eval_ms,
        }


@dataclass
class RunResult:
    task: str
    steps: list[StepRecord] = field(default_factory=list)
    status: str = "completed"
    final_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": safe_value(self.task),
            "status": self.status,
            "final_message": safe_value(self.final_message),
            "steps": [s.to_dict() for s in self.steps],
        }


class AgentLoop:
    def __init__(
        self,
        planner: Planner,
        router: DecisionRouter | None = None,
        max_steps: int = 12,
        decider: DecisionEngine | None = None,
        tool_registry: ToolRegistry | None = None,
    ):
        self.planner = planner
        self.router = router or DecisionRouter()
        self.max_steps = max_steps
        self.decider = decider or DecisionEngine()
        self.tool_registry = tool_registry or ToolRegistry()

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

            execution_arguments = deepcopy(proposal.arguments)
            req = proposal.to_action_request(self.tool_registry, arguments=execution_arguments)
            if getattr(self.router, "execution_enabled", False):
                enrich = getattr(self.router, "enrich_request", None)
                if callable(enrich):
                    req = enrich(req, execution_arguments)
            t0 = time.perf_counter()
            decision = self.decider.evaluate(req)
            eval_ms = round((time.perf_counter() - t0) * 1000, 4)
            if getattr(self.router, "execution_enabled", False):
                outcome = self.router.route(req, decision, execution_arguments)
            else:
                outcome = self.router.route(req, decision)
            result.steps.append(StepRecord(i, proposal, req, decision, outcome, eval_ms=eval_ms))

            observation = {"last_outcome": outcome.status, "last_decision": decision.decision.value}
            if outcome.execution_result:
                observation["last_result"] = outcome.execution_result.to_observation()
            if getattr(self.router, "execution_enabled", False) and outcome.status in {
                "blocked",
                "awaiting_approval",
                "ask_user",
                "execution_failed",
            }:
                result.status = outcome.status
                result.final_message = outcome.message
                break
        else:
            result.status = "max_steps_reached"
        return result
