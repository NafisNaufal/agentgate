"""Provider-specific tool metadata catalogs."""

from .base import ToolSpec
from .github import GITHUB_TOOL_SPECS
from .google import GMAIL_TOOL_SPECS

ALL_TOOL_SPECS: tuple[ToolSpec, ...] = GITHUB_TOOL_SPECS + GMAIL_TOOL_SPECS

__all__ = ["ToolSpec", "GITHUB_TOOL_SPECS", "GMAIL_TOOL_SPECS", "ALL_TOOL_SPECS"]
