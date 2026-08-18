"""Gmail tool metadata, separate from provider execution code.

``content_fields`` is the security-critical part: it tells the ActionRequest builder
which arguments carry scannable content and the router which ones may be rewritten
when a decision is SANITIZE. A Gmail tool registered without it would be evaluated
against an empty payload - the guardrail would see a send with no body.
"""

from .base import ToolSpec


GMAIL_TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "gmail_search",
        "Gmail",
        content_fields=("q",),
        description="Search messages. Read-only: matches nothing, changes nothing.",
    ),
    ToolSpec(
        "gmail_archive",
        "Gmail",
        # Archiving only removes the INBOX label, so it can be undone. Whether a given
        # archive is a *bulk* action is inferred per-call by the action-intent
        # detector from the id list, not hardcoded here - otherwise archiving a single
        # message would demand approval.
        content_fields=("message_ids",),
        description="Archive messages by removing the INBOX label.",
    ),
    ToolSpec(
        "gmail_send",
        "Gmail",
        rollback_available=False,
        default_risk_hints=("external_send",),
        content_fields=("to", "subject", "body", "cc", "bcc"),
        description="Send an email to an external recipient. Cannot be undone.",
    ),
)
