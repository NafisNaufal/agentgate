"""Decision Router / Enforcement (PRD F9).

Turns a DecisionResponse into an actual outcome: execute, block, queue for approval,
sanitize-then-execute, or ask the user. This is the layer that guarantees BLOCK /
NEED_APPROVAL / SANITIZE / ASK_USER are never ignored.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .approval import ApprovalItem, ApprovalQueue
from .audit import AuditLog
from .executors import Executor, ExecutionResult
from .schemas import ActionRequest, Decision, DecisionResponse


@dataclass
class EnforcementOutcome:
    status: str                         # executed / executed_sanitized / blocked / awaiting_approval / ask_user / failed
    decision: Decision
    executed: bool = False
    execution_result: ExecutionResult | None = None
    approval: ApprovalItem | None = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "decision": self.decision.value,
            "executed": self.executed,
            "execution_result": self.execution_result.to_dict() if self.execution_result else None,
            "approval_id": self.approval.approval_id if self.approval else None,
            "message": self.message,
        }


class DecisionRouter:
    def __init__(self, executor: Executor, approval_queue: ApprovalQueue, audit: AuditLog):
        self.executor = executor
        self.approvals = approval_queue
        self.audit = audit

    def route(self, req: ActionRequest, decision: DecisionResponse) -> EnforcementOutcome:
        d = decision.decision

        if d == Decision.BLOCK:
            self.audit.update(decision.audit_id, execution_status="blocked")
            return EnforcementOutcome(
                status="blocked", decision=d, message="Action blocked by AgentGate"
            )

        if d == Decision.ASK_USER:
            self.audit.update(decision.audit_id, execution_status="ask_user")
            return EnforcementOutcome(
                status="ask_user", decision=d, message="User confirmation required before continuing"
            )

        if d == Decision.NEED_APPROVAL:
            item = self.approvals.enqueue(req, decision)
            self.audit.update(decision.audit_id, execution_status="awaiting_approval")
            return EnforcementOutcome(
                status="awaiting_approval",
                decision=d,
                approval=item,
                message=f"Queued for human approval ({item.approval_id})",
            )

        # ALLOW or SANITIZE -> execute (sanitized payload for SANITIZE)
        payload = decision.sanitized_payload if d == Decision.SANITIZE else None
        result = self.executor.execute(req, payload=payload)
        status = "executed_sanitized" if d == Decision.SANITIZE else "executed"
        self.audit.update(
            decision.audit_id,
            execution_status="executed" if result.ok else "failed",
            execution_result=result.to_dict(),
        )
        return EnforcementOutcome(
            status=status if result.ok else "failed",
            decision=d,
            executed=result.ok,
            execution_result=result,
            message="Executed" + (" with sanitized payload" if d == Decision.SANITIZE else ""),
        )

    def resolve_approval(self, approval_id: str, action: str, **kwargs: Any) -> EnforcementOutcome:
        """Apply a reviewer decision and execute if approved/edited."""
        item = self.approvals.get(approval_id)
        if not item:
            return EnforcementOutcome(status="failed", decision=Decision.NEED_APPROVAL,
                                      message=f"Unknown approval {approval_id}")
        if action == "reject":
            self.approvals.reject(approval_id, **kwargs)
            self.audit.update(item.audit_id, reviewer_status="rejected", execution_status="blocked")
            return EnforcementOutcome(status="blocked", decision=Decision.NEED_APPROVAL,
                                      approval=item, message="Reviewer rejected the action")

        if action == "edit":
            self.approvals.edit(approval_id, **kwargs)
            payload = item.edited_payload
            reviewer_status = "edited"
        else:  # approve
            self.approvals.approve(approval_id, **kwargs)
            payload = item.decision.sanitized_payload
            reviewer_status = "approved"

        result = self.executor.execute(item.request, payload=payload)
        self.audit.update(
            item.audit_id,
            reviewer_status=reviewer_status,
            execution_status="executed" if result.ok else "failed",
            execution_result=result.to_dict(),
        )
        return EnforcementOutcome(
            status="executed" if result.ok else "failed",
            decision=Decision.NEED_APPROVAL,
            executed=result.ok,
            execution_result=result,
            approval=item,
            message=f"Reviewer {reviewer_status}; executed",
        )
