"""Tool metadata used to enrich untrusted planner proposals."""

from __future__ import annotations

from .tool_specs import ALL_TOOL_SPECS, ToolSpec


_DEFAULT_TOOLS = ALL_TOOL_SPECS


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
