"""Tool metadata used to enrich untrusted planner proposals."""

from __future__ import annotations

from .tool_specs import GITHUB_TOOL_SPECS, ToolSpec


_EXAMPLE_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("gmail_send", "Gmail", rollback_available=False,
             default_risk_hints=("external_send",), description="Send an email (external, irreversible)."),
    ToolSpec("gmail_search", "Gmail", description="Search the inbox (read-only)."),
)


_DEFAULT_TOOLS = _EXAMPLE_TOOLS + GITHUB_TOOL_SPECS


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
        self._by_name[spec.name] = spec
