"""Approval queue & SafetyGuard.

Holds high-risk actions (NEED_APPROVAL) until a human approves, rejects, or edits
them. The loop never executes a pending action until a reviewer acts.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .schemas import ActionRequest, DecisionResponse


@dataclass
class ApprovalItem:
    approval_id: str
    audit_id: str
    request: ActionRequest
    decision: DecisionResponse
    status: str = "pending"          # pending / approved / rejected / edited
    reviewer: str = ""
    note: str = ""
    edited_payload: str | None = None
    created_at: float = field(default_factory=time.time)
    resolved_at: float | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "audit_id": self.audit_id,
            "status": self.status,
            "action": f"{self.request.action_type} -> {self.request.target or self.request.tool_name}",
            "risk_level": self.decision.risk_level.value,
            "reasons": self.decision.reasons,
            "sanitized_preview": self.decision.sanitized_payload,
        }


class ApprovalQueue:
    def __init__(self) -> None:
        self._items: dict[str, ApprovalItem] = {}

    def enqueue(self, req: ActionRequest, decision: DecisionResponse) -> ApprovalItem:
        approval_id = "apr_" + uuid.uuid4().hex[:10]
        item = ApprovalItem(
            approval_id=approval_id,
            audit_id=decision.audit_id,
            request=req,
            decision=decision,
        )
        self._items[approval_id] = item
        return item

    def pending(self) -> list[ApprovalItem]:
        return [i for i in self._items.values() if i.status == "pending"]

    def get(self, approval_id: str) -> ApprovalItem | None:
        return self._items.get(approval_id)

    def approve(self, approval_id: str, reviewer: str = "reviewer", note: str = "") -> ApprovalItem:
        return self._resolve(approval_id, "approved", reviewer, note)

    def reject(self, approval_id: str, reviewer: str = "reviewer", note: str = "") -> ApprovalItem:
        return self._resolve(approval_id, "rejected", reviewer, note)

    def edit(
        self, approval_id: str, edited_payload: str, reviewer: str = "reviewer", note: str = ""
    ) -> ApprovalItem:
        item = self._resolve(approval_id, "edited", reviewer, note)
        item.edited_payload = edited_payload
        return item

    def _resolve(self, approval_id: str, status: str, reviewer: str, note: str) -> ApprovalItem:
        item = self._items[approval_id]
        item.status = status
        item.reviewer = reviewer
        item.note = note
        item.resolved_at = time.time()
        return item
