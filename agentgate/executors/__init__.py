"""Executors: the seam the Data Engineer track fills with real connectors.

DS builds against this interface; DE swaps the MockExecutor for real Gmail / Google
Calendar / GitHub / Stripe-sandbox / Telegram / Playwright implementations later.
Nothing in the guardrail core depends on a real executor existing.
"""

from .base import Executor, ExecutionResult
from .mock import MockExecutor

__all__ = ["Executor", "ExecutionResult", "MockExecutor"]
