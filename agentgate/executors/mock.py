"""MockExecutor: deterministic stand-in for real API/browser execution.

Simulates a small, realistic latency and returns plausible structured output so the
end-to-end loop, audit log, and raw-vs-guarded benchmark all work tonight with zero
external dependencies or credentials.
"""

from __future__ import annotations

import random
import time

from ..action_space import is_executable
from ..schemas import ActionRequest
from .base import ExecutionResult, Executor

# Rough simulated latencies (seconds) per backend so the benchmark has something real
# to measure. DE's real connectors will replace these numbers.
_API_LATENCY = (0.015, 0.060)
_BROWSER_LATENCY = (0.080, 0.220)


class MockExecutor(Executor):
    def __init__(self, seed: int | None = 7, simulate_latency: bool = True):
        self._rng = random.Random(seed)
        self.simulate_latency = simulate_latency

    def execute(self, req: ActionRequest, *, payload: str | None = None) -> ExecutionResult:
        if not is_executable(req):
            return ExecutionResult(ok=True, output={"noop": req.action_type}, via="mock")

        via = "browser" if req.action_type.startswith("BROWSER") else "api"
        lo, hi = _BROWSER_LATENCY if via == "browser" else _API_LATENCY
        t0 = time.perf_counter()
        if self.simulate_latency:
            time.sleep(self._rng.uniform(lo, hi))
        latency = (time.perf_counter() - t0) * 1000

        output = {
            "simulated": True,
            "action_type": req.action_type,
            "target": req.target or req.tool_name,
            "payload_used": payload if payload is not None else req.payload_summary,
        }
        return ExecutionResult(ok=True, output=output, latency_ms=round(latency, 4), via="mock")
