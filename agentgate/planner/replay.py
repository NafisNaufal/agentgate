"""ReplayPlanner: yields pre-recorded proposals from a scenario.

This is the default planner. It makes the demo fully reproducible and key-free: the
scenario file lists the exact tool calls the agent "proposes", and AgentGate evaluates
each one. Perfect for showcases, tests, and the latency benchmark.
"""

from __future__ import annotations

from .base import Planner, Proposal


class ReplayPlanner(Planner):
    def __init__(self, steps: list[dict] | None = None):
        self._steps = list(steps or [])
        self._i = 0

    @property
    def exhausted(self) -> bool:
        return self._i >= len(self._steps)

    def load(self, steps: list[dict]) -> None:
        self._steps = list(steps)
        self._i = 0

    def propose(self, task: str, observation: dict | None = None) -> Proposal:
        if self.exhausted:
            return Proposal(action_type="DONE", arguments={}, rationale="No more steps")
        step = self._steps[self._i]
        self._i += 1
        return Proposal(
            action_type=step["action_type"],
            arguments=step.get("arguments", {}),
            rationale=step.get("rationale", ""),
            confidence=step.get("confidence", 1.0),
            domain=step.get("domain", "generic"),
            target_system=step.get("target_system", ""),
            risk_hint=step.get("risk_hint", []),
            rollback_available=step.get("rollback_available", True),
        )
