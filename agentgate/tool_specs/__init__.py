"""Provider-specific tool metadata catalogs."""

from .base import ToolSpec
from .github import GITHUB_TOOL_SPECS

__all__ = ["ToolSpec", "GITHUB_TOOL_SPECS"]
