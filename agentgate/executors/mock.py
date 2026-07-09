"""MockExecutor: UNIMPLEMENTED PLACEHOLDER for the Data Engineering (DE) track.

============================================================================
 OWNERSHIP: Data Engineering (DE), per PRD F7 (Playwright Browser Executor)
 and F8 (API Executor). DS built the guardrail engine and the Executor
 interface (agentgate/executors/base.py) that everything above this layer
 (loop, router, benchmark, CLI) is written against — but DS does not
 implement real execution. That is DE's deliverable.
============================================================================

TODO(DE): implement real connectors here (or in a new module of your own,
e.g. agentgate/executors/playwright_executor.py / gmail.py / github.py),
subclassing `Executor` from agentgate/executors/base.py:

    class PlaywrightExecutor(Executor):
        def execute(self, req: ActionRequest, *, payload: str | None = None) -> ExecutionResult:
            ...  # real Gmail/GitHub/Stripe API calls, or real Playwright
                 # browser_open/click/type/select/submit/screenshot

Until that lands, every code path that reaches execution (CLI `run`,
`benchmark`, `plan`, and the `TestLoopAndAudit`/`TestBenchmark` tests) will
raise NotImplementedError on purpose — this is not a bug. It marks exactly
where DE's work begins. See README.md "Ownership: DS vs DA vs DE" for the
full breakdown.
"""

from __future__ import annotations

from ..schemas import ActionRequest
from .base import ExecutionResult, Executor


class MockExecutor(Executor):
    """Placeholder Executor. Raises until DE implements real execution.

    Kept as a class (not deleted) so the DS-built interface — loop.py, router.py,
    benchmark.py, cli.py — has something to import and construct against. Only the
    body of `execute()` is unimplemented; that is the DE deliverable.
    """

    def __init__(self, seed: int | None = 7, simulate_latency: bool = True):
        # Kept for signature compatibility with callers; unused by the placeholder.
        self.seed = seed
        self.simulate_latency = simulate_latency

    def execute(self, req: ActionRequest, *, payload: str | None = None) -> ExecutionResult:
        raise NotImplementedError(
            "MockExecutor is a placeholder for the Data Engineering (DE) track "
            "(PRD F7/F8: Playwright Browser Executor + API Executor). DS has built "
            "and tested the guardrail engine up to this point — see README.md. "
            "To implement: subclass Executor in agentgate/executors/base.py and "
            f"handle action_type={req.action_type!r} target_system={req.target_system!r} "
            "with a real API call or Playwright action."
        )
