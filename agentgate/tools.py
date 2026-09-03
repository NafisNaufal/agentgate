"""Tool metadata used to enrich untrusted planner proposals."""

from __future__ import annotations

from .tool_specs import ALL_TOOL_SPECS, ToolSpec


_DEFAULT_TOOLS = ALL_TOOL_SPECS


class ToolRegistrationError(ValueError):
    """Raised when a registration would replace an already-registered tool's metadata."""


class ToolRegistry:
    def __init__(self, tools: tuple[ToolSpec, ...] = _DEFAULT_TOOLS):
        self._by_name: dict[str, ToolSpec] = {t.name: t for t in tools}

    def get(self, name: str) -> ToolSpec | None:
        return self._by_name.get(name)

    def is_registered(self, name: str) -> bool:
        return name in self._by_name

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def register(self, spec: ToolSpec) -> None:
        """Add a new tool's trusted metadata.

        Registered metadata is the guardrail's only record of what a tool is
        actually allowed to do - rollback_available, default_risk_hints,
        content_fields - so nothing at runtime may silently redefine it once set.
        A second register() call for an already-registered name raises rather than
        replacing: the alternative (keep the original, ignore the new spec) fails
        without leaving any diagnostic trail, and a caller trying to weaken a
        tool's metadata is exactly the case worth surfacing loudly, not absorbing
        quietly. Register a distinct name, or construct a fresh ToolRegistry.
        """
        if spec.name in self._by_name:
            raise ToolRegistrationError(
                f"{spec.name!r} is already registered; tool metadata cannot be "
                "replaced once set. Register a distinct tool name instead."
            )
        self._by_name[spec.name] = spec
