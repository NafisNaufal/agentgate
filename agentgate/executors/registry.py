"""Executor dispatcher with independently registerable providers."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from ..schemas import ActionRequest
from .base import ExecutionResult, Executor


class ExecutorRegistry:
    """Routes action types and exact API tool names to executor instances."""

    def __init__(self) -> None:
        self._actions: dict[str, Executor] = {}
        self._tools: dict[str, Executor] = {}

    def register_action(self, action_type: str, executor: Executor) -> None:
        self._actions[action_type] = executor

    def register_tool(self, tool_name: str, executor: Executor) -> None:
        self._tools[tool_name] = executor

    def resolve(self, action_type: str, arguments: Mapping[str, Any]) -> Executor | None:
        if action_type == "API_CALL":
            return self._tools.get(str(arguments.get("tool_name", "")))
        return self._actions.get(action_type)

    def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
        executor = self.resolve(action_type, arguments)
        if executor is None:
            name = arguments.get("tool_name") if action_type == "API_CALL" else action_type
            return ExecutionResult(
                success=False,
                status="executor_not_found",
                summary="No executor is registered for this action",
                error=f"No executor registered for {name!s}",
            )
        try:
            result = executor.execute(action_type, arguments)
            if not isinstance(result, ExecutionResult):
                return ExecutionResult(
                    success=False,
                    status="invalid_executor_result",
                    summary="Executor returned an invalid result",
                    error="Executors must return ExecutionResult",
                )
            return result
        except Exception as exc:
            return ExecutionResult(
                success=False,
                status="executor_error",
                summary="Executor failed without completing the action",
                error=f"{type(exc).__name__}: {exc}",
            )

    def enrich_request(
        self,
        request: ActionRequest,
        arguments: Mapping[str, Any],
    ) -> ActionRequest:
        """Merge executor-owned, side-effect-free context before guardrail evaluation."""
        executor = self.resolve(request.action_type, arguments)
        enrich = getattr(executor, "enrich_request", None) if executor else None
        if not callable(enrich):
            return request
        try:
            enriched = enrich(request, arguments)
            _copy_execution_metadata(request, enriched)
            return enriched
        except Exception:
            enriched = replace(
                request,
                confidence=0.0,
                rollback_available=False,
                risk_hint=list(dict.fromkeys([*request.risk_hint, "destructive_action"])),
                content_context="\n".join(
                    part
                    for part in (
                        request.content_context,
                        "Trusted executor context was unavailable; fail closed",
                    )
                    if part
                ),
            )
            _copy_execution_metadata(request, enriched)
            return enriched

    def close(self) -> None:
        """Close each distinct executor that exposes a close method."""
        seen: set[int] = set()
        for executor in (*self._actions.values(), *self._tools.values()):
            if id(executor) in seen:
                continue
            seen.add(id(executor))
            close = getattr(executor, "close", None)
            if callable(close):
                close()


def build_default_executor_registry() -> ExecutorRegistry:
    """Build the MVP registry without importing Playwright itself."""
    from ..tool_specs import GITHUB_TOOL_SPECS
    from .filesystem import FileSystemExecutor
    from .github import GitHubExecutor
    from .playwright import BROWSER_ACTIONS, PlaywrightExecutor

    registry = ExecutorRegistry()
    filesystem = FileSystemExecutor()
    github = GitHubExecutor()
    browser = PlaywrightExecutor()
    registry.register_action("FILE_READ", filesystem)
    for spec in GITHUB_TOOL_SPECS:
        registry.register_tool(spec.name, github)
    for action_type in BROWSER_ACTIONS:
        registry.register_action(action_type, browser)
    return registry


def _copy_execution_metadata(source: ActionRequest, target: ActionRequest) -> None:
    for name in ("_execution_argument_fingerprint", "_execution_content_fields"):
        value = getattr(source, name, None)
        if value is not None:
            setattr(target, name, value)
