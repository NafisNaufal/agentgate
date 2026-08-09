"""Optional real-execution layer for AgentGate."""

from .base import ExecutionResult, Executor
from .filesystem import FileSystemExecutor
from .github import GitHubExecutor
from .playwright import PlaywrightExecutor
from .registry import ExecutorRegistry, build_default_executor_registry

__all__ = [
    "ExecutionResult",
    "Executor",
    "ExecutorRegistry",
    "FileSystemExecutor",
    "GitHubExecutor",
    "PlaywrightExecutor",
    "build_default_executor_registry",
]
