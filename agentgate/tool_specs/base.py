"""Shared metadata contract for registered tools."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    target_system: str
    action_type: str = "API_CALL"
    channel: str = "api"
    rollback_available: bool = True
    default_risk_hints: tuple[str, ...] = ()
    description: str = ""
