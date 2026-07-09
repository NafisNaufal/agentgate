"""Executor interface (the DS/DE seam).

An Executor actually performs an action once AgentGate has allowed it. The core only
needs ``execute``; DE implements the real API/browser side behind the same signature.

OWNERSHIP: this interface is DS-authored (part of the guardrail contract). The
implementation is DE's (PRD F7 Playwright Browser Executor, F8 API Executor).
See agentgate/executors/mock.py for the current placeholder and TODO.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schemas import ActionRequest


@dataclass
class ExecutionResult:
    ok: bool
    output: Any = None
    error: str = ""
    latency_ms: float = 0.0
    via: str = ""  # "api" / "browser" / "mock"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "output": self.output,
            "error": self.error,
            "latency_ms": self.latency_ms,
            "via": self.via,
        }


class Executor:
    """Base executor. DE subclasses this with real connectors."""

    def execute(self, req: ActionRequest, *, payload: str | None = None) -> ExecutionResult:  # pragma: no cover
        raise NotImplementedError

    def supports(self, req: ActionRequest) -> bool:
        return True
