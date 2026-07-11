"""Tool Registry - definition (PRD Phase 2: "define ... tool registry").

Phase 2 calls for *defining* the tool registry's shape, distinct from prototyping it
(Phase 3, which covers the loop/planner/parser/router/baseline evaluation only) or
fully building it out with a complete tool catalog and safety-enrichment logic wired
into the planner (Sprint 1-2).

This module defines that shape - what a registered tool looks like, and the lookup
interface - with a couple of illustrative entries. It is not yet consulted by the
loop or planner; wiring it into ActionRequest enrichment is later work.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    target_system: str
    action_type: str = "API_CALL"
    channel: str = "api"  # api | browser | file
    rollback_available: bool = True
    default_risk_hints: tuple[str, ...] = ()
    description: str = ""


# Illustrative entries only, proving the shape - not the full catalog.
_EXAMPLE_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("gmail_send", "Gmail", rollback_available=False,
             default_risk_hints=("external_send",), description="Send an email (external, irreversible)."),
    ToolSpec("gmail_search", "Gmail", description="Search the inbox (read-only)."),
)


class ToolRegistry:
    def __init__(self, tools: tuple[ToolSpec, ...] = _EXAMPLE_TOOLS):
        self._by_name: dict[str, ToolSpec] = {t.name: t for t in tools}

    def get(self, name: str) -> ToolSpec | None:
        return self._by_name.get(name)

    def is_registered(self, name: str) -> bool:
        return name in self._by_name

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def register(self, spec: ToolSpec) -> None:
        self._by_name[spec.name] = spec
