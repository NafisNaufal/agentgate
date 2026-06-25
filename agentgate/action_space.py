"""Action Space Validator.

Every proposed tool call must use a registered action verb with the right shape.
Anything outside the vocabulary is rejected before it reaches the guardrail (PRD:
"Any tool call outside the registered vocabulary is rejected by the Action Space
Validator").
"""

from __future__ import annotations

from .schemas import ACTION_TYPES, ActionRequest

# Required argument keys per action verb (for proposals coming from the planner).
_REQUIRED_ARGS: dict[str, tuple[str, ...]] = {
    "API_CALL": ("tool_name",),
    "BROWSER_OPEN": ("url",),
    "BROWSER_SNAPSHOT": (),
    "BROWSER_CLICK": ("element_id",),
    "BROWSER_TYPE": ("element_id", "value"),
    "BROWSER_SELECT": ("element_id", "option"),
    "BROWSER_SUBMIT": ("element_id",),
    "BROWSER_SCREENSHOT": (),
    "FILE_READ": ("path",),
    "ASK_USER": ("question",),
    "NEED_APPROVAL": ("action_description",),
    "SANITIZE": ("payload",),
    "DONE": (),
    "FAIL": (),
}


class ActionSpaceError(ValueError):
    """Raised when a proposed action is not in the registered vocabulary."""


def validate_proposal(action_type: str, arguments: dict | None = None) -> None:
    """Validate a raw planner proposal. Raises ActionSpaceError if invalid."""
    arguments = arguments or {}
    if action_type not in ACTION_TYPES:
        raise ActionSpaceError(
            f"Unknown action_type '{action_type}'. Allowed: {sorted(ACTION_TYPES)}"
        )
    missing = [a for a in _REQUIRED_ARGS.get(action_type, ()) if not arguments.get(a)]
    if missing:
        raise ActionSpaceError(
            f"Action '{action_type}' missing required argument(s): {missing}"
        )


def is_terminal(action_type: str) -> bool:
    """DONE / FAIL end the agent loop."""
    return action_type in {"DONE", "FAIL"}


def is_executable(req: ActionRequest) -> bool:
    """Whether this action would actually touch an external system if allowed."""
    return req.action_type in {
        "API_CALL",
        "BROWSER_OPEN",
        "BROWSER_CLICK",
        "BROWSER_TYPE",
        "BROWSER_SELECT",
        "BROWSER_SUBMIT",
        "BROWSER_SCREENSHOT",
        "FILE_READ",
    }
