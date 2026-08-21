"""Tests for machine-checkable AgentGate scenario regressions."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agentgate.planner import ReplayPlanner
from agentgate.router import DecisionRouter
from agentgate.scenario_runner import (
    SCENARIO_DIR,
    EvaluationReport,
    Scenario,
    ScenarioResult,
    ScenarioStep,
    ScenarioValidationError,
    build_agentgate_loop,
    execute_scenario,
    format_report,
    load_scenario,
    main,
    run_scenarios,
)
from agentgate.schemas import Decision, RiskLevel
from tests.fake_audit import FakeAuditStore
from tests.fake_llm import fake_chat_json


def _scenario(expected_decision: Decision = Decision.ALLOW) -> Scenario:
    return Scenario(
        name="unit_scenario",
        title="Unit scenario",
        task="Inspect the current page",
        steps=(
            ScenarioStep(
                id="inspect_page",
                action={"action_type": "BROWSER_SNAPSHOT", "arguments": {}},
                expected_decision=expected_decision,
                expected_risk_level=RiskLevel.LOW,
            ),
        ),
        path=Path("unit_scenario.json"),
    )


def _loop_with(decision: Decision, risk_level: RiskLevel):
    record = SimpleNamespace(
        proposal=ReplayPlanner(
            [{"action_type": "BROWSER_SNAPSHOT", "arguments": {}}]
        ).propose("Inspect the current page"),
        decision=SimpleNamespace(decision=decision, risk_level=risk_level),
        rejected_reason="",
    )
    loop = SimpleNamespace()
    loop.run = unittest.mock.Mock(return_value=SimpleNamespace(steps=[record]))
    return loop


class TestScenarioParsing(unittest.TestCase):
    def test_all_packaged_scenarios_load(self):
        scenarios = [load_scenario(path) for path in sorted(SCENARIO_DIR.glob("*.json"))]
        self.assertEqual(len(scenarios), 4)
        self.assertTrue(all(scenario.steps for scenario in scenarios))
        self.assertTrue(all(step.id for scenario in scenarios for step in scenario.steps))

    def test_missing_expected_fields_fail(self):
        base = {
            "name": "invalid",
            "task": "Inspect page",
            "steps": [
                {
                    "id": "step_1",
                    "action_type": "BROWSER_SNAPSHOT",
                    "arguments": {},
                }
            ],
        }
        invalid_expectations = (None, {}, {"decision": "ALLOW"}, {"risk_level": "LOW"})
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            for expected in invalid_expectations:
                data = json.loads(json.dumps(base))
                if expected is not None:
                    data["steps"][0]["expected"] = expected
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.subTest(expected=expected):
                    with self.assertRaises(ScenarioValidationError):
                        load_scenario(path)

    def test_unknown_fields_and_invalid_metadata_fail(self):
        base = {
            "name": "invalid",
            "task": "Inspect page",
            "steps": [
                {
                    "id": "step_1",
                    "action_type": "BROWSER_SNAPSHOT",
                    "arguments": {},
                    "expected": {"decision": "ALLOW", "risk_level": "LOW"},
                }
            ],
        }
        mutations = (
            lambda data: data.update({"unknown": True}),
            lambda data: data["steps"][0].update({"risk_hints": ["bulk_action"]}),
            lambda data: data["steps"][0]["expected"].update({"risk": "LOW"}),
            lambda data: data["steps"][0].update({"confidence": "high"}),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            for mutate in mutations:
                data = json.loads(json.dumps(base))
                mutate(data)
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.subTest(data=data):
                    with self.assertRaises(ScenarioValidationError):
                        load_scenario(path)


class TestScenarioExecution(unittest.TestCase):
    @patch("agentgate.decision.build_audit_store", FakeAuditStore)
    @patch("agentgate.detectors.llm_client.chat_json", side_effect=fake_chat_json)
    def test_packaged_expectations_match_agentgate_pipeline(self, _chat_json):
        report = run_scenarios()
        self.assertEqual(report.exit_code, 0, format_report(report))
        self.assertEqual(len(report.scenarios), 4)

    def test_runner_builds_existing_agentgate_flow_and_compares_output(self):
        fake_loop = _loop_with(Decision.ALLOW, RiskLevel.LOW)
        with patch("agentgate.scenario_runner.AgentLoop", return_value=fake_loop) as loop_class:
            result = execute_scenario(_scenario())

        planner, router = loop_class.call_args.args
        self.assertIsInstance(planner, ReplayPlanner)
        self.assertIsInstance(router, DecisionRouter)
        fake_loop.run.assert_called_once_with("Inspect the current page")
        self.assertTrue(result.passed)
        self.assertTrue(result.steps[0].passed)

    @patch("agentgate.decision.build_audit_store", FakeAuditStore)
    def test_loop_capacity_includes_every_action_and_implicit_terminal(self):
        step = _scenario().steps[0]
        scenario = Scenario(
            name="long_scenario",
            title="Long scenario",
            task="Inspect repeatedly",
            steps=tuple(
                ScenarioStep(
                    id=f"inspect_{index}",
                    action=step.action,
                    expected_decision=step.expected_decision,
                    expected_risk_level=step.expected_risk_level,
                )
                for index in range(13)
            ),
            path=Path("long_scenario.json"),
        )
        self.assertEqual(build_agentgate_loop(scenario).max_steps, 14)

    def test_full_proposal_mismatch_fails_alignment(self):
        fake_loop = _loop_with(Decision.ALLOW, RiskLevel.LOW)
        fake_loop.run.return_value.steps[0].proposal.arguments = {"unexpected": True}
        result = execute_scenario(_scenario(), loop_factory=lambda _scenario: fake_loop)
        self.assertFalse(result.passed)
        self.assertIn("did not match", result.steps[0].error)

    def test_decision_or_risk_mismatch_fails_comparison(self):
        for decision, risk_level in (
            (Decision.BLOCK, RiskLevel.LOW),
            (Decision.ALLOW, RiskLevel.HIGH),
        ):
            with self.subTest(decision=decision, risk_level=risk_level):
                result = execute_scenario(
                    _scenario(),
                    loop_factory=lambda _scenario: _loop_with(decision, risk_level),
                )
                self.assertFalse(result.passed)
                self.assertFalse(result.steps[0].passed)

    def test_report_shows_expected_actual_and_result(self):
        result = execute_scenario(
            _scenario(),
            loop_factory=lambda _scenario: _loop_with(Decision.ALLOW, RiskLevel.LOW),
        )
        output = format_report(EvaluationReport([result]))
        self.assertIn("Expected:\ndecision: ALLOW", output)
        self.assertIn("Actual:\ndecision: ALLOW", output)
        self.assertIn("Result: PASS", output)
        self.assertIn("Exit code: 0", output)

    def test_web_console_uses_structured_expectation_summary(self):
        from agentgate.web.app import Console

        scenarios = Console.__new__(Console).scenarios()
        expected = {scenario["name"]: scenario["expected"] for scenario in scenarios}
        self.assertEqual(expected["ambiguous_cleanup"], "ALLOW -> ASK_USER")
        self.assertTrue(all(expected.values()))


class TestScenarioFailureExitCode(unittest.TestCase):
    def test_intentional_mismatch_returns_nonzero(self):
        data = {
            "name": "intentional_mismatch",
            "task": "Inspect page",
            "steps": [
                {
                    "id": "inspect_page",
                    "action_type": "BROWSER_SNAPSHOT",
                    "arguments": {},
                    "expected": {"decision": "BLOCK", "risk_level": "LOW"},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "mismatch.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            report = run_scenarios(
                Path(temp_dir),
                loop_factory=lambda _scenario: _loop_with(Decision.ALLOW, RiskLevel.LOW),
            )

        self.assertEqual(report.exit_code, 1)
        self.assertFalse(report.scenarios[0].steps[0].passed)
        with patch("agentgate.scenario_runner.run_scenarios", return_value=report):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([]), 1)

    def test_loading_failure_returns_nonzero(self):
        report = EvaluationReport([ScenarioResult(name="broken", error="invalid scenario")])
        self.assertEqual(report.exit_code, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
