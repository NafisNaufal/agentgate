"""Background run manager for the Demo Console.

A single guarded action costs six sequential detector calls - measured at roughly 400s
on the CPU-only dev box - so a run cannot happen inside a request. Runs execute on a
worker thread and the UI polls for progress; ``AgentLoop.on_step`` feeds each decided
step through as it lands rather than at the end.

Runs are serialized behind one lock. Concurrent runs would contend for the same local
model and make every run slower without finishing any sooner.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from ..executors.base import safe_value
from ..loop import AgentLoop, StepRecord


@dataclass
class Job:
    id: str
    label: str
    kind: str  # "scenario" | "chat"
    status: str = "queued"  # queued | running | done | error
    total: int = 0  # expected number of rows, when known up front (eval)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    result_status: str = ""
    final_message: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "status": self.status,
            "started_at": self.started_at,
            "elapsed": round((self.finished_at or time.time()) - self.started_at, 1),
            "steps": self.steps,
            "total": self.total,
            "result_status": self.result_status,
            "final_message": self.final_message,
            "error": self.error,
        }


def step_to_dict(step: StepRecord) -> dict[str, Any]:
    """The subset of a step the console renders, already sanitized."""
    decision = step.decision
    return {
        "index": step.index,
        "action_type": step.proposal.action_type,
        "rejected_reason": safe_value(step.rejected_reason),
        "eval_ms": step.eval_ms,
        "decision": decision.decision.value if decision else None,
        "risk_level": decision.risk_level.value if decision else None,
        "risk_score": decision.risk_score if decision else None,
        "reasons": [safe_value(r) for r in decision.reasons] if decision else [],
        "triggered_policies": list(decision.triggered_policies) if decision else [],
        "sensitive_entities": (
            [{"kind": e.kind, "severity": e.severity} for e in decision.sensitive_entities]
            if decision
            else []
        ),
        "sanitized_payload": decision.sanitized_payload if decision else None,
        "audit_id": decision.audit_id if decision else "",
        "outcome": step.outcome.to_dict() if step.outcome else None,
    }


class JobManager:
    def __init__(self, max_history: int = 25) -> None:
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._max_history = max_history

    def busy(self) -> bool:
        return self._run_lock.locked()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def recent(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._jobs[j].to_dict() for j in reversed(self._order) if j in self._jobs]

    def active(self) -> Job | None:
        """The job currently queued or running, if any.

        The console polls this on load: a browser reload must not orphan a run that is
        still going server-side, which is exactly what happens when the only handle on
        it is a variable in the page.
        """
        with self._lock:
            for job_id in reversed(self._order):
                job = self._jobs.get(job_id)
                if job and job.status in {"queued", "running"}:
                    return job
        return None

    def submit(
        self,
        label: str,
        kind: str,
        work: Callable[[Callable[[dict[str, Any]], None]], tuple[str, str]],
    ) -> Job:
        """Queue a unit of work.

        ``work`` receives an ``emit`` callback for incremental rows and returns
        (result_status, final_message). Generic rather than loop-specific so the DA
        evaluation, which is a sequence of evaluate() calls rather than an agent run,
        uses the same queue, run lock and polling contract.
        """
        job = Job(id="job_" + uuid.uuid4().hex[:10], label=label, kind=kind)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self._max_history:
                self._jobs.pop(self._order.pop(0), None)
        threading.Thread(target=self._run, args=(job, work), daemon=True).start()
        return job

    def _run(
        self,
        job: Job,
        work: Callable[[Callable[[dict[str, Any]], None]], tuple[str, str]],
    ) -> None:
        with self._run_lock:
            job.status = "running"
            try:
                status, message = work(job.steps.append)
                job.result_status = status
                job.final_message = safe_value(message)
                job.status = "done"
            except Exception as exc:
                # Surface the type and message, never a traceback: the console is
                # network-reachable and tracebacks leak paths and internals.
                job.error = f"{type(exc).__name__}: {exc}"
                job.status = "error"
            finally:
                job.finished_at = time.time()
