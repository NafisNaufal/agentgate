"""Audit log.

Every evaluated action is recorded with its request, decision, reasons, entities,
reviewer/execution status, and timestamp (PRD F14). Default sink is a JSONL file plus
an in-memory list so the CLI/dashboard can read it back. DE can later point this at a
real SQLite/Postgres store by subclassing or swapping ``sink``.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .schemas import ActionRequest, DecisionResponse


@dataclass
class AuditRecord:
    audit_id: str
    timestamp: float
    request: dict[str, Any]
    decision: dict[str, Any]
    execution_status: str = "pending"   # pending / executed / blocked / failed / awaiting_approval
    reviewer_status: str = "none"       # none / approved / rejected / edited
    execution_result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.timestamp)),
            "request": self.request,
            "decision": self.decision,
            "execution_status": self.execution_status,
            "reviewer_status": self.reviewer_status,
            "execution_result": self.execution_result,
        }


class AuditLog:
    def __init__(self, path: str | Path | None = None, sink: Callable[[dict], None] | None = None):
        self.records: list[AuditRecord] = []
        self._by_id: dict[str, AuditRecord] = {}
        self.path = Path(path) if path else None
        self._sink = sink
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, req: ActionRequest, decision: DecisionResponse) -> str:
        audit_id = "aud_" + uuid.uuid4().hex[:12]
        decision.audit_id = audit_id
        rec = AuditRecord(
            audit_id=audit_id,
            timestamp=time.time(),
            request=req.to_dict(),
            decision=decision.to_dict(),
            execution_status="awaiting_approval"
            if decision.decision.value == "NEED_APPROVAL"
            else "pending",
        )
        self.records.append(rec)
        self._by_id[audit_id] = rec
        self._flush(rec)
        return audit_id

    def update(
        self,
        audit_id: str,
        *,
        execution_status: str | None = None,
        reviewer_status: str | None = None,
        execution_result: dict | None = None,
    ) -> None:
        rec = self._by_id.get(audit_id)
        if not rec:
            return
        if execution_status is not None:
            rec.execution_status = execution_status
        if reviewer_status is not None:
            rec.reviewer_status = reviewer_status
        if execution_result is not None:
            rec.execution_result = execution_result
        self._flush(rec)

    def get(self, audit_id: str) -> AuditRecord | None:
        return self._by_id.get(audit_id)

    def completeness(self) -> float:
        """Fraction of records that carry request, decision, status and timestamp (F14)."""
        if not self.records:
            return 1.0
        complete = sum(
            1
            for r in self.records
            if r.request and r.decision and r.execution_status and r.timestamp
        )
        return round(complete / len(self.records), 4)

    def _flush(self, rec: AuditRecord) -> None:
        line = json.dumps(rec.to_dict())
        if self.path:
            # Append-only JSONL; simplest durable sink for the MVP.
            with self.path.open("a") as fh:
                fh.write(line + "\n")
        if self._sink:
            self._sink(rec.to_dict())
