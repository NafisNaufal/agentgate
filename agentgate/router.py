"""Decision routing and optional guarded execution."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from .executors import ExecutionResult, ExecutorRegistry
from .planner.base import execution_argument_fingerprint
from .sanitizer import sanitize
from .schemas import ActionRequest, Decision, DecisionResponse


@dataclass
class EnforcementOutcome:
    status: str
    message: str
    execution_result: ExecutionResult | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "status": self.status,
            "message": sanitize(self.message),
        }
        if self.execution_result:
            result["execution_result"] = self.execution_result.to_dict()
        return result


class DecisionRouter:
    def __init__(
        self,
        executors: ExecutorRegistry | None = None,
        *,
        execute: bool = False,
    ) -> None:
        self.executors = executors or ExecutorRegistry()
        self.execution_enabled = execute

    def enrich_request(
        self,
        request: ActionRequest,
        arguments: Mapping[str, Any],
    ) -> ActionRequest:
        return self.executors.enrich_request(request, arguments)

    def route(
        self,
        req: ActionRequest,
        decision: DecisionResponse,
        arguments: Mapping[str, Any] | None = None,
    ) -> EnforcementOutcome:
        if decision.decision == Decision.BLOCK:
            return EnforcementOutcome("blocked", "Action blocked by the guardrail")
        if decision.decision == Decision.NEED_APPROVAL:
            return EnforcementOutcome(
                "awaiting_approval",
                "Action requires human approval (approval queue: Data Engineering scope)",
            )
        if decision.decision == Decision.ASK_USER:
            return EnforcementOutcome("ask_user", "User confirmation required before continuing")
        if decision.decision not in {Decision.ALLOW, Decision.SANITIZE}:
            return EnforcementOutcome("blocked", "Unknown decision value; action failed closed")
        if not self.execution_enabled:
            if decision.decision == Decision.SANITIZE:
                return EnforcementOutcome(
                    "sanitize_pending",
                    "Payload sanitized; would execute the redacted version in execution mode",
                )
            return EnforcementOutcome(
                "would_execute",
                "Allowed; dry-run mode did not execute the action",
            )

        return self._finish_execution(req, decision, arguments)

    def execute_after_human_approval(
        self,
        req: ActionRequest,
        decision: DecisionResponse,
        arguments: Mapping[str, Any] | None,
    ) -> EnforcementOutcome:
        """Execute a NEED_APPROVAL/ASK_USER action after a synchronous human 'yes' in
        this same session - the interactive chat's equivalent of Claude Code's own
        tool-permission prompt. route() never does this on its own: a bare NEED_APPROVAL
        or ASK_USER decision always routes to a pending status regardless of
        execution_enabled, by design. BLOCK can never be approved around this way.
        """
        if decision.decision not in {Decision.NEED_APPROVAL, Decision.ASK_USER}:
            raise ValueError(
                "execute_after_human_approval is only for NEED_APPROVAL/ASK_USER decisions, "
                f"got {decision.decision}"
            )
        if not self.execution_enabled:
            return EnforcementOutcome(
                "would_execute",
                "Approved; dry-run mode did not execute the action",
            )
        return self._finish_execution(req, decision, arguments)

    def _finish_execution(
        self,
        req: ActionRequest,
        decision: DecisionResponse,
        arguments: Mapping[str, Any] | None,
    ) -> EnforcementOutcome:
        if arguments is None:
            result = ExecutionResult(
                False,
                "missing_arguments",
                "Executor did not receive structured proposal arguments",
                error="Original proposal arguments are required for real execution",
            )
            return EnforcementOutcome("execution_failed", result.summary, result)

        if not _arguments_match_request(req, arguments):
            result = ExecutionResult(
                False,
                "argument_mismatch",
                "Evaluated action no longer matches its execution arguments",
                error="Structured arguments changed after guardrail evaluation",
            )
            return EnforcementOutcome("execution_failed", result.summary, result)

        execution_arguments: Mapping[str, Any] = deepcopy(dict(arguments))
        if decision.decision == Decision.SANITIZE:
            execution_arguments = _sanitized_arguments(req, arguments, decision.sanitized_payload)
            if execution_arguments is None:
                result = ExecutionResult(
                    False,
                    "sanitize_unsupported",
                    "Sanitized action was not executed",
                    error="No content-bearing execution argument could be sanitized",
                )
                return EnforcementOutcome("execution_failed", result.summary, result)

        result = self.executors.execute(req.action_type, execution_arguments)
        status = "executed" if result.success else "execution_failed"
        return EnforcementOutcome(status, sanitize(result.summary), result)


def _sanitized_arguments(
    req: ActionRequest,
    arguments: Mapping[str, Any],
    sanitized_payload: str | None,
) -> dict[str, Any] | None:
    if sanitized_payload is None:
        return None
    updated = deepcopy(dict(arguments))

    if req.action_type == "BROWSER_TYPE" and isinstance(updated.get("value"), str):
        updated["value"] = sanitized_payload
        return updated
    if req.action_type != "API_CALL":
        return None

    allowed_keys = getattr(req, "_execution_content_fields", None)
    if not allowed_keys:
        return None
    content_keys = [
        key
        for key in allowed_keys
        if isinstance(updated.get(key), str)
    ]
    unsupported_keys = (
        "value",
        "payload",
        "body",
        "content",
        "title",
        "description",
        "action_description",
        "question",
    )
    for key in unsupported_keys:
        if key not in allowed_keys and isinstance(updated.get(key), str):
            if sanitize(updated[key]) != updated[key]:
                return None
    files = updated.get("files")
    file_contents: list[tuple[str, dict[str, Any]]] = []
    changed = False
    if isinstance(files, dict):
        sanitized_files: dict[str, Any] = {}
        for name, value in files.items():
            safe_name = sanitize(str(name))
            changed = changed or safe_name != name
            if safe_name in sanitized_files:
                return None
            if isinstance(value, dict) and isinstance(value.get("content"), str):
                file_contents.append((name, value))
            elif isinstance(value, str):
                redacted = sanitize(value)
                changed = changed or redacted != value
                value = redacted
            sanitized_files[safe_name] = value
        updated["files"] = files = sanitized_files

    for key in content_keys:
        redacted = sanitize(updated[key])
        changed = changed or redacted != updated[key]
        updated[key] = redacted
    for _, value in file_contents:
        redacted = sanitize(value["content"])
        changed = changed or redacted != value["content"]
        value["content"] = redacted
    return updated if changed else None


def _arguments_match_request(req: ActionRequest, arguments: Mapping[str, Any]) -> bool:
    fingerprint = getattr(req, "_execution_argument_fingerprint", None)
    return bool(fingerprint) and execution_argument_fingerprint(dict(arguments)) == fingerprint
