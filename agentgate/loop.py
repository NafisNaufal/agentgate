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

import json
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable

from .action_space import ActionSpaceError, is_terminal
from .audit import (
    STAGE_OBSERVATION_SCREEN,
    STAGE_TASK_SCREEN,
    STAGE_TERMINAL_SCREEN,
)
from .decision import DecisionEngine
from .executors.base import ExecutionResult, safe_value
from .planner.base import Planner, Proposal
from .router import DecisionRouter, EnforcementOutcome
from .schemas import ActionRequest, Decision, DecisionResponse, RiskLevel
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
        proposal_arguments = safe_value(self.proposal.arguments)
        if self.decision and self.decision.sensitive_entities:
            proposal_arguments = _opaque_arguments(self.proposal.arguments)
            if request:
                for key in ("target", "payload_summary", "content_context", "raw_payload"):
                    request[key] = "[REDACTED_SENSITIVE_CONTENT]"
        return {
            "index": self.index,
            "proposal": {
                "action_type": self.proposal.action_type,
                "arguments": proposal_arguments,
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
        has_sensitive_content = any(
            step.decision and step.decision.sensitive_entities
            for step in self.steps
        )
        return {
            "task": (
                "[REDACTED_SENSITIVE_CONTENT]"
                if has_sensitive_content
                else safe_value(self.task)
            ),
            "status": self.status,
            "final_message": (
                "[REDACTED_SENSITIVE_CONTENT]"
                if has_sensitive_content
                else safe_value(self.final_message)
            ),
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
        on_step: Callable[[StepRecord], None] | None = None,
    ):
        self.planner = planner
        self.router = router or DecisionRouter()
        self.max_steps = max_steps
        self.decider = decider or DecisionEngine()
        self.tool_registry = tool_registry or ToolRegistry()
        # Fired as each step is decided. A run takes minutes on CPU-only inference,
        # so anything watching it (the web console) needs progress, not just a result.
        self.on_step = on_step

    def run(self, task: str, observation: dict | None = None) -> RunResult:
        task_screen = self.decider.evaluate(
            ActionRequest(action_type="TASK_CONTEXT", payload_summary=task),
            STAGE_TASK_SCREEN,
        )
        display_task = (
            task
            if task_screen.decision == Decision.ALLOW
            and not task_screen.sensitive_entities
            else "Task text was withheld by AgentGate"
        )
        result = RunResult(task=display_task)
        for i in range(self.max_steps):
            try:
                proposal = self.planner.propose(task, observation)
            except Exception as exc:  # planner unavailable: fail this step, not the run
                self._record(
                    result,
                    StepRecord(
                        i, Proposal(action_type="FAIL"), rejected_reason=f"Planner error: {exc}"
                    ),
                )
                result.status = "failed"
                result.final_message = f"Planner unavailable: {exc}"
                break

            try:
                proposal.validate()
            except ActionSpaceError as exc:
                self._record(result, StepRecord(i, proposal, rejected_reason=str(exc)))
                continue

            if is_terminal(proposal.action_type):
                terminal_message = proposal.arguments.get(
                    "result_summary",
                    proposal.arguments.get("reason", proposal.rationale),
                )
                terminal_decision = self.decider.evaluate(
                    ActionRequest(
                        action_type=proposal.action_type,
                        payload_summary=str(terminal_message),
                    ),
                    STAGE_TERMINAL_SCREEN,
                )
                if proposal.action_type == "FAIL":
                    result.status = "failed"
                elif not getattr(self.router, "execution_enabled", False):
                    intervened = any(
                        step.decision
                        and step.decision.decision
                        in {
                            Decision.BLOCK,
                            Decision.SANITIZE,
                            Decision.NEED_APPROVAL,
                            Decision.ASK_USER,
                        }
                        for step in result.steps
                    )
                    result.status = (
                        "dry_run_intervention" if intervened else "dry_run_complete"
                    )
                else:
                    result.status = "completed"
                result.final_message = (
                    "Terminal planner output was withheld by AgentGate"
                    if terminal_decision.decision != Decision.ALLOW
                    or terminal_decision.sensitive_entities
                    else str(terminal_message)
                )
                break

            if proposal.action_type in {"ASK_USER", "NEED_APPROVAL"}:
                control_decision = _control_decision(proposal)
                outcome = self.router.route(
                    proposal.to_action_request(self.tool_registry),
                    control_decision,
                )
                self._record(
                    result,
                    StepRecord(i, proposal, decision=control_decision, outcome=outcome),
                )
                result.status = outcome.status
                result.final_message = outcome.message
                break

            if (
                getattr(self.router, "execution_enabled", False)
                and proposal.action_type == "API_CALL"
                and not self.tool_registry.is_registered(
                    str(proposal.arguments.get("tool_name", ""))
                )
            ):
                reason = "Real API execution requires registered trusted tool metadata"
                self._record(result, StepRecord(i, proposal, rejected_reason=reason))
                result.status = "failed"
                result.final_message = reason
                break

            try:
                execution_arguments = deepcopy(proposal.arguments)
                req = proposal.to_action_request(
                    self.tool_registry,
                    arguments=execution_arguments,
                )
            except (TypeError, ValueError) as exc:
                reason = f"Invalid action request: {exc}"
                self._record(result, StepRecord(i, proposal, rejected_reason=reason))
                continue
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
            # Close the audit record for this step: the decision was recorded at
            # evaluate() time, the enforcement outcome is only known now (PRD F14
            # requires both the decision and the execution status).
            self.decider.audit_store.update(
                decision.audit_id,
                execution_status=outcome.status,
                execution_result=(
                    outcome.execution_result.to_dict() if outcome.execution_result else None
                ),
            )
            self._record(result, StepRecord(i, proposal, req, decision, outcome, eval_ms=eval_ms))

            observation = {"last_outcome": outcome.status, "last_decision": decision.decision.value}
            if outcome.execution_result:
                observation["last_result"] = self._screen_execution_observation(
                    req,
                    outcome.execution_result,
                )
                outcome.message = outcome.execution_result.summary
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

    def _record(self, result: RunResult, step: StepRecord) -> None:
        result.steps.append(step)
        if self.on_step:
            try:
                self.on_step(step)
            except Exception:
                pass  # a watcher must never break the run it is watching

    def _screen_execution_observation(
        self,
        request: ActionRequest,
        execution_result: ExecutionResult,
    ) -> dict[str, Any]:
        safe_result = execution_result.to_dict()
        serialized = json.dumps(safe_result, ensure_ascii=True)
        observation_request = ActionRequest(
            action_type=request.action_type,
            domain=request.domain,
            target_system=request.target_system,
            tool_name=request.tool_name,
            target=request.target,
            payload_summary=serialized[:120],
            raw_payload=serialized,
            content_context="Content returned by an executor before planner observation",
            risk_hint=list(request.risk_hint),
            rollback_available=request.rollback_available,
            confidence=1.0,
        )
        decision = self.decider.evaluate(observation_request, STAGE_OBSERVATION_SCREEN)
        if decision.decision == Decision.ALLOW:
            execution_result.summary = safe_result["summary"]
            execution_result.data = safe_result["data"]
            execution_result.error = safe_result["error"]
            return safe_result
        if decision.decision == Decision.SANITIZE and decision.sanitized_payload:
            execution_result.status = "sanitized_observation"
            execution_result.summary = "Executor output was sanitized before planner observation"
            execution_result.data = decision.sanitized_payload
            execution_result.error = None
            return {
                "success": execution_result.success,
                "status": "sanitized_observation",
                "summary": "Executor output was sanitized before planner observation",
                "data": decision.sanitized_payload,
                "error": None,
            }
        execution_result.status = "observation_quarantined"
        execution_result.summary = "Executor output was withheld from the planner by AgentGate"
        execution_result.data = None
        execution_result.error = None
        return {
            "success": execution_result.success,
            "status": "observation_quarantined",
            "summary": "Executor output was withheld from the planner by AgentGate",
            "data": None,
            "error": None,
        }


def _control_decision(proposal: Proposal) -> DecisionResponse:
    decision = (
        Decision.ASK_USER
        if proposal.action_type == "ASK_USER"
        else Decision.NEED_APPROVAL
    )
    return DecisionResponse(
        decision=decision,
        risk_level=RiskLevel.LOW if decision == Decision.ASK_USER else RiskLevel.HIGH,
        risk_score=0.0 if decision == Decision.ASK_USER else 0.6,
        reasons=[proposal.rationale or "Planner requested a guarded control step"],
        next_step="ask_user" if decision == Decision.ASK_USER else "approval",
    )


def _opaque_arguments(arguments: Any) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        return {"content": "[REDACTED_SENSITIVE_CONTENT]"}
    structural_keys = {"tool_name", "owner", "repo", "issue_number", "element_id", "public"}
    safe = {
        str(key): safe_value(value)
        for key, value in arguments.items()
        if key in structural_keys
    }
    safe["content"] = "[REDACTED_SENSITIVE_CONTENT]"
    return safe
