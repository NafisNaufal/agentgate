#!/usr/bin/env python3
"""Run every packaged AgentGate scenario as a regression check."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentgate.scenario_runner import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
