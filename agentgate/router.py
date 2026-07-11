"""Decision Router (Phase 3 prototype).

Enforces the decision returned by the baseline evaluator so BLOCK / NEED_APPROVAL /
ASK_USER / SANITIZE are never silently ignored. There is no real Executor or
Approval Queue yet - those are Sprint 1+ deliverables - so the router's job at this
stage is to translate a decision into the correct next step, proving the enforcement
concept without yet performing real execution or persistence.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schemas import ActionRequest, Decision, DecisionResponse


@dataclass
class EnforcementOutcome:
    status: str
    message: str


class DecisionRouter:
    def route(self, req: ActionRequest, decision: DecisionResponse) -> EnforcementOutcome:
        if decision.decision == Decision.BLOCK:
            return EnforcementOutcome("blocked", "Action blocked by the baseline evaluator")
        if decision.decision == Decision.NEED_APPROVAL:
            return EnforcementOutcome(
                "awaiting_approval",
                "Action requires human approval (approval queue: Sprint 1+ scope)",
            )
        if decision.decision == Decision.ASK_USER:
            return EnforcementOutcome("ask_user", "User confirmation required before continuing")
        if decision.decision == Decision.SANITIZE:
            return EnforcementOutcome(
                "sanitize_pending",
                "Payload sanitization required (sanitizer: Sprint 1+ scope)",
            )
        return EnforcementOutcome(
            "would_execute",
            "Allowed - would run via a real Executor (Sprint 1+ Data Engineering scope)",
        )
