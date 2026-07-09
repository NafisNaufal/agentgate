"""Tool Registry (PRD: "LLM Planner + Tool Registry").

The *action vocabulary* (agentgate/action_space.py) fixes the verbs a planner may use
(API_CALL, BROWSER_CLICK, ...). The *tool registry* here catalogs the concrete API
tools a planner may name in `tool_name` (gmail_archive, github_create_gist, ...), and
records each tool's:

  - target_system        (Gmail, GitHub, Stripe Sandbox, ...)
  - action_type          (usually API_CALL; FILE_READ for the local file tool)
  - channel              (api / browser / file)
  - rollback_available   (is the effect undoable?)
  - default_risk_hints   (risk that is INHERENT to the tool regardless of payload,
                          e.g. gmail_send is always an external send)

Two jobs:
  1. Validation/introspection: is a proposed tool_name known? (`is_registered`)
  2. Enrichment: fill missing ActionRequest fields and apply safety defaults
     (`enrich`) so the guardrail does not rely on the planner to volunteer that, say,
     a Stripe charge is payment-related or that a Telegram send is irreversible.

Browser and local-file actions are covered by the action vocabulary (their own verbs),
so the registry focuses on API tools.

OWNERSHIP: the registry LOGIC (ToolSpec shape, enrichment/safety-tightening) is DS's
job (part of the planner/loop layer, F2). The CONTENT of `_DEFAULT_TOOLS` below
(which tools exist, pricing/auth/feasibility) overlaps with DA's API feasibility
research (PRD: "API matrix"). TODO(DA): review/expand this catalog against your
feasibility map and flag any tool here that isn't actually available, or any real
tool that's missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .schemas import ActionRequest


@dataclass(frozen=True)
class ToolSpec:
    name: str
    target_system: str
    action_type: str = "API_CALL"
    channel: str = "api"  # api | browser | file
    rollback_available: bool = True
    default_risk_hints: tuple[str, ...] = ()
    description: str = ""


_DEFAULT_TOOLS: tuple[ToolSpec, ...] = (
    # --- Gmail ---------------------------------------------------------
    ToolSpec("gmail_search", "Gmail", description="Search the inbox (read-only)."),
    ToolSpec("gmail_read_message", "Gmail", description="Read a single message (read-only)."),
    ToolSpec("gmail_draft", "Gmail", description="Create a draft (not sent)."),
    ToolSpec("gmail_archive", "Gmail", description="Archive messages (reversible)."),
    ToolSpec("gmail_delete", "Gmail", rollback_available=False,
             default_risk_hints=("destructive_action",), description="Delete messages (irreversible)."),
    ToolSpec("gmail_send", "Gmail", rollback_available=False,
             default_risk_hints=("external_send",), description="Send an email (external, irreversible)."),
    # --- Google Calendar ----------------------------------------------
    ToolSpec("calendar_list_events", "Google Calendar", description="List events (read-only)."),
    ToolSpec("calendar_create_event", "Google Calendar", description="Create an event (reversible)."),
    ToolSpec("calendar_update_event", "Google Calendar", description="Update an event (reversible)."),
    ToolSpec("calendar_delete_event", "Google Calendar", rollback_available=False,
             default_risk_hints=("destructive_action",), description="Delete an event."),
    # --- GitHub --------------------------------------------------------
    ToolSpec("github_read_file", "GitHub", default_risk_hints=("source_code",),
             description="Read a repository file."),
    ToolSpec("github_create_gist", "GitHub", default_risk_hints=("external_send", "source_code"),
             description="Publish a gist (external code egress)."),
    ToolSpec("github_create_issue", "GitHub", default_risk_hints=("external_send",),
             description="Open an issue (external)."),
    ToolSpec("github_create_pr", "GitHub", default_risk_hints=("external_send", "source_code"),
             description="Open a pull request (external code)."),
    # --- Stripe Sandbox ------------------------------------------------
    ToolSpec("stripe_create_charge", "Stripe Sandbox", rollback_available=False,
             default_risk_hints=("payment_related",), description="Create a charge (financial)."),
    ToolSpec("stripe_create_refund", "Stripe Sandbox", rollback_available=False,
             default_risk_hints=("payment_related", "destructive_action"), description="Issue a refund."),
    # --- Telegram ------------------------------------------------------
    ToolSpec("telegram_send_message", "Telegram", rollback_available=False,
             default_risk_hints=("external_send",), description="Send a Telegram message (external)."),
    # --- Local filesystem ---------------------------------------------
    ToolSpec("file_read", "local file", action_type="FILE_READ", channel="file",
             description="Read a local file."),
)


class ToolRegistry:
    def __init__(self, tools: tuple[ToolSpec, ...] = _DEFAULT_TOOLS):
        self._by_name: dict[str, ToolSpec] = {t.name: t for t in tools}

    def get(self, name: str) -> ToolSpec | None:
        return self._by_name.get(name)

    def is_registered(self, name: str) -> bool:
        return name in self._by_name

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def by_system(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for spec in self._by_name.values():
            out.setdefault(spec.target_system, []).append(spec.name)
        return {k: sorted(v) for k, v in sorted(out.items())}

    def register(self, spec: ToolSpec) -> None:
        self._by_name[spec.name] = spec

    def enrich(self, req: ActionRequest) -> ActionRequest:
        """Fill missing contract fields and apply the tool's inherent safety defaults.

        Only *tightens* safety: fills target_system if empty, forces
        rollback_available=False for irreversible tools, and unions the tool's inherent
        risk hints. Never loosens anything the planner already set.
        """
        spec = self._by_name.get(req.tool_name)
        if not spec:
            return req
        if not req.target_system:
            req.target_system = spec.target_system
        if not spec.rollback_available:
            req.rollback_available = False
        for hint in spec.default_risk_hints:
            if hint not in req.risk_hint:
                req.risk_hint.append(hint)
        return req


DEFAULT_TOOL_REGISTRY = ToolRegistry()
