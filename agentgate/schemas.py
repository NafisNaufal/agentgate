"""Core data contracts for AgentGate.

These two schemas are the stable interface the whole system is built around:

  ActionRequest   - the standard input AgentGate evaluates (a proposed tool call,
                    normalized). F3 in the PRD: this is the *shared DS/DE contract*.
  DecisionResponse - the standard output AgentGate returns.

Kept as plain dataclasses (stdlib only) so the engine runs with no third-party deps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """Supported decisions (PRD section 9)."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    NEED_APPROVAL = "NEED_APPROVAL"
    SANITIZE = "SANITIZE"
    ASK_USER = "ASK_USER"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Action vocabulary (PRD "Action Space"). Anything outside this is rejected by the
# Action Space Validator before it ever reaches the guardrail.
ACTION_TYPES = {
    "API_CALL",
    "BROWSER_OPEN",
    "BROWSER_SNAPSHOT",
    "BROWSER_CLICK",
    "BROWSER_TYPE",
    "BROWSER_SELECT",
    "BROWSER_SUBMIT",
    "BROWSER_SCREENSHOT",
    "FILE_READ",
    "ASK_USER",
    "NEED_APPROVAL",
    "SANITIZE",
    "DONE",
    "FAIL",
}

# Risk hints the planner / detectors may attach (PRD ActionRequest.risk_hint).
RISK_HINTS = {
    "external_send",
    "payment_related",
    "source_code",
    "bulk_action",
    "destructive_action",
}


@dataclass
class ActionRequest:
    """Standard input evaluated by AgentGate (PRD section 8).

    Only ``action_type`` is strictly required; everything else is best-effort
    context the planner / runtime supplies. Detectors and the policy engine read
    these fields to make a decision.
    """

    action_type: str
    domain: str = "generic"
    target_system: str = ""
    tool_name: str = ""
    target: str = ""
    payload_summary: str = ""
    content_context: str = ""
    risk_hint: list[str] = field(default_factory=list)
    rollback_available: bool = True
    confidence: float = 1.0
    # Raw payload kept internally for detection/sanitization; never required to be
    # the same as payload_summary (which is the redacted/compact view).
    raw_payload: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.risk_hint, str):
            self.risk_hint = [self.risk_hint] if self.risk_hint else []
        # The text detectors scan: prefer raw payload, fall back to the summary.
        if not self.raw_payload:
            self.raw_payload = self.payload_summary

    @property
    def scan_text(self) -> str:
        """All free text a detector should inspect, de-duplicated.

        raw_payload and payload_summary are often identical; including both would
        double-count every detected entity, so we keep only distinct fragments.
        """
        seen: list[str] = []
        for t in (self.raw_payload, self.payload_summary, self.content_context, self.target):
            if t and t not in seen:
                seen.append(t)
        return "\n".join(seen)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionRequest":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SensitiveEntity:
    """A single detected sensitive item."""

    kind: str            # e.g. "EMAIL", "API_KEY", "PRIVATE_KEY", "SOURCE_CODE"
    snippet: str         # short, already-truncated preview
    detector: str        # which detector found it
    severity: str = "MEDIUM"  # LOW / MEDIUM / HIGH / CRITICAL

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DecisionResponse:
    """Standard output returned by AgentGate (PRD section 9)."""

    decision: Decision
    risk_level: RiskLevel
    risk_score: float
    reasons: list[str] = field(default_factory=list)
    triggered_policies: list[str] = field(default_factory=list)
    sensitive_entities: list[SensitiveEntity] = field(default_factory=list)
    sanitized_payload: str | None = None
    next_step: str = ""
    audit_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        d["risk_level"] = self.risk_level.value
        return d

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
