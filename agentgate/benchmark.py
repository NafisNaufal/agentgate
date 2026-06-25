"""Raw-vs-Guarded latency benchmark (PRD F11 / F12).

Compares executing a set of actions directly ("raw") against running them through
AgentGate first ("guarded"), and reports P50/P95 latencies plus overhead. The MVP
target: guardrail overhead stays small enough that the agent feels usable
(PRD: <= 20% on protected API actions where feasible; eval P95 <= 250ms rule-based).
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any

from .engine import AgentGate
from .executors import Executor, MockExecutor
from .schemas import ActionRequest


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 4)


@dataclass
class BenchmarkReport:
    n: int
    raw_p50: float
    raw_p95: float
    guarded_p50: float
    guarded_p95: float
    eval_p50: float
    eval_p95: float
    overhead_pct_p50: float
    overhead_pct_p95: float
    slowest_eval_ms: float
    slowest_action: str

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    def render(self) -> str:
        return (
            f"Raw-vs-Guarded Benchmark  (n={self.n} actions)\n"
            f"  raw      P50/P95 : {self.raw_p50:8.2f} / {self.raw_p95:8.2f} ms\n"
            f"  guarded  P50/P95 : {self.guarded_p50:8.2f} / {self.guarded_p95:8.2f} ms\n"
            f"  gate eval P50/P95: {self.eval_p50:8.2f} / {self.eval_p95:8.2f} ms\n"
            f"  overhead P50/P95 : {self.overhead_pct_p50:7.1f}% / {self.overhead_pct_p95:6.1f}%\n"
            f"  slowest eval     : {self.slowest_eval_ms:.2f} ms  ({self.slowest_action})"
        )


def run_benchmark(
    requests: list[ActionRequest],
    *,
    repeats: int = 20,
    executor: Executor | None = None,
) -> BenchmarkReport:
    executor = executor or MockExecutor(simulate_latency=True)
    # Separate gate with audit disabled-to-disk so file IO doesn't pollute timings.
    gate = AgentGate()

    raw_lat: list[float] = []
    guarded_lat: list[float] = []
    eval_lat: list[float] = []
    slowest_eval, slowest_action = 0.0, ""

    for _ in range(repeats):
        for req in requests:
            # raw: execute directly, no guardrail
            t0 = time.perf_counter()
            executor.execute(req)
            raw_lat.append((time.perf_counter() - t0) * 1000)

            # guarded: evaluate, then execute. We execute unconditionally here so the
            # comparison isolates the *latency tax* of the guardrail (eval added before
            # every action), holding execution work constant against the raw path. The
            # guardrail's safety value (preventing some executions) is measured by the
            # decision metrics, not by this latency number.
            t1 = time.perf_counter()
            decision = gate.evaluate(req, write_audit=False)
            eval_ms = gate.last_timings.evaluate_ms
            executor.execute(req, payload=decision.sanitized_payload)
            guarded_lat.append((time.perf_counter() - t1) * 1000)

            eval_lat.append(eval_ms)
            if eval_ms > slowest_eval:
                slowest_eval, slowest_action = eval_ms, f"{req.action_type}/{req.domain}"

    raw_p50, raw_p95 = _pct(raw_lat, 0.5), _pct(raw_lat, 0.95)
    g_p50, g_p95 = _pct(guarded_lat, 0.5), _pct(guarded_lat, 0.95)
    return BenchmarkReport(
        n=len(requests) * repeats,
        raw_p50=raw_p50,
        raw_p95=raw_p95,
        guarded_p50=g_p50,
        guarded_p95=g_p95,
        eval_p50=_pct(eval_lat, 0.5),
        eval_p95=_pct(eval_lat, 0.95),
        overhead_pct_p50=round((g_p50 - raw_p50) / raw_p50 * 100, 2) if raw_p50 else 0.0,
        overhead_pct_p95=round((g_p95 - raw_p95) / raw_p95 * 100, 2) if raw_p95 else 0.0,
        slowest_eval_ms=round(slowest_eval, 4),
        slowest_action=slowest_action,
    )
