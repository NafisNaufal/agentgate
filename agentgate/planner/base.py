"""Planner interface and the Proposal -> ActionRequest bridge (F2 / F3).

A Proposal is the planner's raw suggestion. ``to_action_request`` normalizes it into
the shared ActionRequest contract that detectors and policies evaluate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..action_space import validate_proposal
from ..schemas import ActionRequest


@dataclass
class Proposal:
    action_type: str
    arguments: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    confidence: float = 1.0

    # Optional planner-supplied context that helps the ActionRequest builder.
    domain: str = "generic"
    target_system: str = ""
    risk_hint: list[str] = field(default_factory=list)
    rollback_available: bool = True

    def validate(self) -> None:
        validate_proposal(self.action_type, self.arguments)

    def to_action_request(self) -> ActionRequest:
        """ActionRequest builder (F3): normalize a proposal into the shared schema."""
        args = self.arguments
        target = (
            args.get("url")
            or args.get("path")
            or args.get("element_id")
            or args.get("tool_name")
            or ""
        )
        payload = ""
        for key in ("value", "payload", "action_description", "question", "body", "content"):
            if args.get(key):
                payload = str(args[key])
                break
        return ActionRequest(
            action_type=self.action_type,
            domain=self.domain,
            target_system=self.target_system,
            tool_name=args.get("tool_name", ""),
            target=str(target),
            payload_summary=_summarize(payload),
            raw_payload=payload,
            content_context=self.rationale,
            risk_hint=list(self.risk_hint),
            rollback_available=self.rollback_available,
            confidence=self.confidence,
        )


def _summarize(text: str, n: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


class Planner:
    def propose(self, task: str, observation: dict | None = None) -> Proposal:  # pragma: no cover
        raise NotImplementedError
