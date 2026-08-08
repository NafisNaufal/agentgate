"""GitHub tool metadata, separate from provider execution code."""

from .base import ToolSpec


GITHUB_TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "github_read_repo",
        "GitHub",
        description="Read safe repository metadata.",
    ),
    ToolSpec(
        "github_read_file",
        "GitHub",
        description="Read a UTF-8 file from a repository.",
    ),
    ToolSpec(
        "github_create_issue",
        "GitHub",
        rollback_available=False,
        default_risk_hints=("external_send",),
        description="Create an externally visible repository issue.",
    ),
    ToolSpec(
        "github_create_issue_comment",
        "GitHub",
        rollback_available=False,
        default_risk_hints=("external_send",),
        description="Post an externally visible issue comment.",
    ),
    ToolSpec(
        "github_create_gist",
        "GitHub",
        rollback_available=False,
        default_risk_hints=("external_send", "source_code"),
        description="Create an external gist containing one or more files.",
    ),
)
