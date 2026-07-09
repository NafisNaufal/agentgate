"""AgentGate facade.

Ties the decision engine to the audit log and per-stage latency profiling (F11).
This is the single object the agent loop talks to:

    gate = AgentGate()
    decision = gate.evaluate(action_request)

``evaluate`` is the hot path the raw-vs-guarded benchmark measures.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .audit import AuditLog
from .decision import DecisionEngine
from .detectors import Detector
from .policy import PolicyEngine
from .schemas import ActionRequest, DecisionResponse


@dataclass
class StageTimings:
    """Per-evaluation latency breakdown in milliseconds."""

    evaluate_ms: float = 0.0
    audit_ms: float = 0.0

    @property
    def total_ms(self) -> float:
        return round(self.evaluate_ms + self.audit_ms, 4)


class AgentGate:
    def __init__(
        self,
        detectors: list[Detector] | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_log: AuditLog | None = None,
    ):
        self.decider = DecisionEngine(detectors=detectors, policy_engine=policy_engine)
        self.audit = audit_log if audit_log is not None else AuditLog()
        self.last_timings = StageTimings()

    def evaluate(self, req: ActionRequest, *, write_audit: bool = True) -> DecisionResponse:
        t0 = time.perf_counter()
        decision = self.decider.evaluate(req)
        t1 = time.perf_counter()
        if write_audit:
            self.audit.record(req, decision)
        t2 = time.perf_counter()

        self.last_timings = StageTimings(
            evaluate_ms=round((t1 - t0) * 1000, 4),
            audit_ms=round((t2 - t1) * 1000, 4),
        )
        return decision
