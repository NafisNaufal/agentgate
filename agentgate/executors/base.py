"""Common contracts for side-effecting AgentGate executors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from ..sanitizer import sanitize


_OBSERVATION_TEXT_LIMIT = 8_000


@dataclass
class ExecutionResult:
    """Structured result returned by every executor."""

    success: bool
    status: str
    summary: str
    data: dict[str, Any] | list[Any] | str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a bounded, sanitized representation suitable for output/audit."""
        return {
            "success": self.success,
            "status": self.status,
            "summary": sanitize(self.summary)[:_OBSERVATION_TEXT_LIMIT],
            "data": safe_value(self.data),
            "error": sanitize(self.error)[:_OBSERVATION_TEXT_LIMIT] if self.error else None,
        }

    def to_observation(self) -> dict[str, Any]:
        """Return the planner-safe form of this result."""
        return self.to_dict()


class Executor(Protocol):
    """Executor interface used by the dispatcher."""

    def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
        ...


def safe_value(value: Any, budget: int = _OBSERVATION_TEXT_LIMIT) -> Any:
    if isinstance(value, str):
        return sanitize(value)[:budget]
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        remaining = budget
        for key, item in value.items():
            if remaining <= 0:
                break
            safe_key = sanitize(str(key))[:200]
            safe[safe_key] = safe_value(item, remaining)
            remaining -= len(str(safe[safe_key]))
        return safe
    if isinstance(value, (list, tuple)):
        safe_list: list[Any] = []
        remaining = budget
        for item in value:
            if remaining <= 0:
                break
            safe_item = safe_value(item, remaining)
            safe_list.append(safe_item)
            remaining -= len(str(safe_item))
        return safe_list
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize(str(value))[:budget]
