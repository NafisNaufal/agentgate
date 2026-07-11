"""AgentGate test suite (stdlib unittest; also runs under pytest).

Phase 3 prototype scope: action space, the baseline evaluator, and the loop/router.
The full detector-suite / policy-engine / tool-registry tests return once those land
(Sprint 1+).

    python -m unittest discover -s tests
    pytest tests/
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from agentgate.action_space import ActionSpaceError, validate_proposal
from agentgate.baseline import evaluate_baseline
from agentgate.loop import AgentLoop
from agentgate.planner import ReplayPlanner
from agentgate.router import DecisionRouter
from agentgate.schemas import ActionRequest, Decision
from agentgate.tools import ToolRegistry, ToolSpec

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios"


def AR(**kw) -> ActionRequest:
    kw.setdefault("action_type", "API_CALL")
    return ActionRequest(**kw)


class TestActionSpace(unittest.TestCase):
    def test_rejects_unknown(self):
        with self.assertRaises(ActionSpaceError):
            validate_proposal("TELEPORT", {})

    def test_requires_args(self):
        with self.assertRaises(ActionSpaceError):
            validate_proposal("BROWSER_CLICK", {})
        validate_proposal("BROWSER_CLICK", {"element_id": "5"})  # ok

    def test_cli_eval_rejects_off_vocabulary_before_evaluating(self):
        # The CLI's `eval` command builds an ActionRequest directly (no Proposal in
        # the loop), so it needs its own tool-call-parser check - this guards against
        # that check silently going missing again.
        import io
        from contextlib import redirect_stdout
        from agentgate.cli import build_parser

        args = build_parser().parse_args(["eval", "TELEPORT"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = args.func(args)
        self.assertEqual(exit_code, 1)
        self.assertIn("REJECTED", buf.getvalue())


class TestBaselineEvaluator(unittest.TestCase):
    def test_clean_action_allows(self):
        d = evaluate_baseline(AR(action_type="BROWSER_SNAPSHOT"))
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_secret_pattern_blocks(self):
        d = evaluate_baseline(AR(payload_summary="key AKIAIOSFODNN7EXAMPLE"))
        self.assertEqual(d.decision, Decision.BLOCK)

    def test_payment_words_need_approval(self):
        d = evaluate_baseline(AR(payload_summary="Your payment of $450 is confirmed"))
        self.assertEqual(d.decision, Decision.NEED_APPROVAL)

    def test_bulk_pattern_need_approval(self):
        d = evaluate_baseline(AR(payload_summary="archive 500 old emails"))
        self.assertEqual(d.decision, Decision.NEED_APPROVAL)

    def test_destructive_word_need_approval(self):
        d = evaluate_baseline(AR(payload_summary="delete the account permanently"))
        self.assertEqual(d.decision, Decision.NEED_APPROVAL)


class TestToolRegistryDefinition(unittest.TestCase):
    """Phase 2 scope: the shape exists and is lookupable. Not yet wired into the
    loop/planner - that integration, and the full tool catalog, is later work."""

    def test_lookup(self):
        reg = ToolRegistry()
        self.assertTrue(reg.is_registered("gmail_send"))
        self.assertFalse(reg.is_registered("made_up_tool"))

    def test_register_new_tool(self):
        reg = ToolRegistry()
        reg.register(ToolSpec("github_read_file", "GitHub"))
        self.assertTrue(reg.is_registered("github_read_file"))


class TestLoop(unittest.TestCase):
    def test_booking_scenario_runs_end_to_end(self):
        scenario = json.loads((SCENARIO_DIR / "booking_message.json").read_text())
        loop = AgentLoop(ReplayPlanner(scenario["steps"]), DecisionRouter())
        result = loop.run(scenario["task"])
        self.assertEqual(result.status, "completed")
        decided = [s.decision.decision for s in result.steps if s.decision]
        self.assertIn(Decision.NEED_APPROVAL, decided)  # payment send step
        self.assertIn(Decision.ALLOW, decided)  # open/snapshot/type steps

    def test_off_vocabulary_step_is_rejected_not_crashed(self):
        loop = AgentLoop(ReplayPlanner([{"action_type": "TELEPORT", "arguments": {}}]))
        result = loop.run("do something invalid")
        self.assertEqual(result.steps[0].rejected_reason != "", True)

    def test_planner_failure_does_not_crash_the_run(self):
        # Custom loop risk (Phase 0): a planner that errors (e.g. a live LLM call
        # timing out) must fail the run gracefully, not raise out of run().
        class BrokenPlanner:
            def propose(self, task, observation=None):
                raise RuntimeError("simulated planner outage")

        loop = AgentLoop(BrokenPlanner())
        result = loop.run("do something")
        self.assertEqual(result.status, "failed")
        self.assertIn("Planner unavailable", result.final_message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
