"""Planner interface and the Proposal -> ActionRequest bridge (F2 / F3)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from ..action_space import validate_proposal
from ..schemas import ActionRequest
from ..tools import ToolRegistry


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

    def to_action_request(
        self,
        tool_registry: ToolRegistry | None = None,
        *,
        arguments: dict[str, Any] | None = None,
    ) -> ActionRequest:
        """ActionRequest builder (F3): normalize a proposal into the shared schema."""
        args = arguments if arguments is not None else self.arguments
        tool_name = str(args.get("tool_name", ""))
        spec = tool_registry.get(tool_name) if tool_registry and self.action_type == "API_CALL" else None
        target = (
            args.get("url")
            or args.get("path")
            or args.get("element_id")
            or args.get("tool_name")
            or ""
        )
        content_fields = spec.content_fields if spec else None
        payload = _payload_text(args, self.action_type, content_fields)
        risk_hints = list(dict.fromkeys([*self.risk_hint, *(spec.default_risk_hints if spec else ())]))
        rollback_available = self.rollback_available
        if spec:
            rollback_available = spec.rollback_available and rollback_available
        request = ActionRequest(
            action_type=self.action_type,
            domain=self.domain,
            target_system=spec.target_system if spec else self.target_system,
            tool_name=tool_name,
            target=str(target),
            payload_summary=_summarize(payload),
            raw_payload=payload,
            content_context=self.rationale,
            risk_hint=risk_hints,
            rollback_available=rollback_available,
            confidence=self.confidence,
        )
        request._execution_argument_fingerprint = execution_argument_fingerprint(args)
        request._execution_content_fields = content_fields
        return request


def _summarize(text: str, n: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _payload_text(
    arguments: dict[str, Any],
    action_type: str = "",
    content_fields: tuple[str, ...] | None = None,
) -> str:
    """Collect content relevant to guardrail scanning without retaining arguments."""
    values: list[str] = []
    keys = content_fields if content_fields is not None else (
        ("value",)
        if action_type == "BROWSER_TYPE"
        else ("content",)
        if action_type == "FILE_WRITE"
        else (
            "value",
            "payload",
            "action_description",
            "question",
            "body",
            "content",
            "title",
            "description",
        )
    )
    for key in keys:
        if key == "files":
            continue
        value = arguments.get(key)
        if value is not None and value != "":
            values.append(str(value))

    files = arguments.get("files")
    if isinstance(files, dict) and (content_fields is None or "files" in content_fields):
        for name, file_data in files.items():
            content = file_data.get("content") if isinstance(file_data, dict) else file_data
            if content is not None:
                values.append(f"{name}\n{content}")
    return "\n".join(values)


def execution_argument_fingerprint(arguments: dict[str, Any]) -> str:
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class Planner:
    def propose(self, task: str, observation: dict | None = None) -> Proposal:  # pragma: no cover
        raise NotImplementedError
