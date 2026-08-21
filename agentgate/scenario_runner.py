"""Machine-checkable regression runner for packaged AgentGate scenarios."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .action_space import is_terminal, validate_proposal
from .loop import AgentLoop
from .planner import ReplayPlanner
from .router import DecisionRouter
from .schemas import Decision, RiskLevel


SCENARIO_DIR = Path(__file__).parent / "scenarios"
_SCENARIO_KEYS = {"name", "title", "domain", "description", "task", "steps"}
_STEP_KEYS = {
    "id",
    "action_type",
    "arguments",
    "domain",
    "target_system",
    "rationale",
    "confidence",
    "risk_hint",
    "rollback_available",
    "expected",
}
_EXPECTED_KEYS = {"decision", "risk_level"}


class ScenarioValidationError(ValueError):
    """Raised when a scenario cannot be used as a regression contract."""


@dataclass(frozen=True)
class ScenarioStep:
    id: str
    action: dict[str, Any]
    expected_decision: Decision
    expected_risk_level: RiskLevel


@dataclass(frozen=True)
class Scenario:
    name: str
    title: str
    task: str
    steps: tuple[ScenarioStep, ...]
    path: Path


@dataclass(frozen=True)
class StepResult:
    id: str
    expected_decision: Decision
    expected_risk_level: RiskLevel
    actual_decision: Decision | None
    actual_risk_level: RiskLevel | None
    error: str = ""

    @property
    def passed(self) -> bool:
        return (
            not self.error
            and self.actual_decision == self.expected_decision
            and self.actual_risk_level == self.expected_risk_level
        )


@dataclass
class ScenarioResult:
    name: str
    steps: list[StepResult] = field(default_factory=list)
    error: str = ""

    @property
    def passed(self) -> bool:
        return not self.error and bool(self.steps) and all(step.passed for step in self.steps)


@dataclass
class EvaluationReport:
    scenarios: list[ScenarioResult]

    @property
    def passed(self) -> bool:
        return bool(self.scenarios) and all(scenario.passed for scenario in self.scenarios)

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1


LoopFactory = Callable[[Scenario], AgentLoop]


def discover_scenarios(scenario_dir: Path = SCENARIO_DIR) -> list[Path]:
    """Return every JSON scenario in deterministic filename order."""
    return sorted(scenario_dir.glob("*.json"))


def expected_summary(scenario: dict[str, Any]) -> str:
    """Format structured step expectations for existing scenario listings."""
    return " -> ".join(
        step["expected"]["decision"]
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
        and isinstance(step.get("expected"), dict)
        and isinstance(step["expected"].get("decision"), str)
    )


def load_scenario(path: Path) -> Scenario:
    """Load and validate one scenario regression contract."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScenarioValidationError(f"{path}: cannot load scenario: {exc}") from exc

    if not isinstance(data, dict):
        raise ScenarioValidationError(f"{path}: scenario must be a JSON object")
    unknown_scenario_keys = set(data) - _SCENARIO_KEYS
    if unknown_scenario_keys:
        raise ScenarioValidationError(
            f"{path}: scenario contains unknown fields: {sorted(unknown_scenario_keys)}"
        )

    name = _required_text(data, "name", path)
    title = data.get("title", name)
    if not isinstance(title, str) or not title:
        raise ScenarioValidationError(f"{path}: field 'title' must be non-empty text")
    for key in ("domain", "description"):
        if key in data and not isinstance(data[key], str):
            raise ScenarioValidationError(f"{path}: field {key!r} must be text")
    task = _required_text(data, "task", path)
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ScenarioValidationError(f"{path}: field 'steps' must be a non-empty list")

    steps: list[ScenarioStep] = []
    seen_ids: set[str] = set()
    for index, raw_step in enumerate(raw_steps, start=1):
        location = f"{path}: step {index}"
        if not isinstance(raw_step, dict):
            raise ScenarioValidationError(f"{location} must be a JSON object")
        unknown_step_keys = set(raw_step) - _STEP_KEYS
        if unknown_step_keys:
            raise ScenarioValidationError(
                f"{location} contains unknown fields: {sorted(unknown_step_keys)}"
            )
        step_id = raw_step.get("id")
        if not isinstance(step_id, str) or not step_id:
            raise ScenarioValidationError(f"{location} requires a non-empty 'id'")
        if step_id in seen_ids:
            raise ScenarioValidationError(f"{location} has duplicate id {step_id!r}")
        seen_ids.add(step_id)

        expected = raw_step.get("expected")
        if not isinstance(expected, dict):
            raise ScenarioValidationError(f"{location} requires an 'expected' object")
        unknown_expected_keys = set(expected) - _EXPECTED_KEYS
        if unknown_expected_keys:
            raise ScenarioValidationError(
                f"{location} expected contains unknown fields: {sorted(unknown_expected_keys)}"
            )
        if "decision" not in expected or "risk_level" not in expected:
            raise ScenarioValidationError(
                f"{location} expected requires 'decision' and 'risk_level'"
            )
        try:
            expected_decision = Decision(expected["decision"])
            expected_risk_level = RiskLevel(expected["risk_level"])
        except (TypeError, ValueError) as exc:
            raise ScenarioValidationError(f"{location} has an invalid expectation: {exc}") from exc

        action = {
            key: value
            for key, value in raw_step.items()
            if key not in {"id", "expected"}
        }
        action_type = action.get("action_type")
        if is_terminal(action_type):
            raise ScenarioValidationError(
                f"{location} is terminal; only evaluated actions belong in scenario steps"
            )
        try:
            validate_proposal(action_type, action.get("arguments"))
        except (TypeError, ValueError) as exc:
            raise ScenarioValidationError(f"{location} has an invalid action: {exc}") from exc
        _validate_action_metadata(action, location)
        steps.append(
            ScenarioStep(
                id=step_id,
                action=action,
                expected_decision=expected_decision,
                expected_risk_level=expected_risk_level,
            )
        )

    return Scenario(name=name, title=title, task=task, steps=tuple(steps), path=path)


def build_agentgate_loop(scenario: Scenario) -> AgentLoop:
    """Build the same dry-run replay flow used by the AgentGate scenario CLI."""
    return AgentLoop(
        ReplayPlanner([step.action for step in scenario.steps]),
        DecisionRouter(),
        max_steps=len(scenario.steps) + 1,
    )


def execute_scenario(
    scenario: Scenario,
    loop_factory: LoopFactory = build_agentgate_loop,
) -> ScenarioResult:
    """Execute and compare every actionable step in one scenario."""
    loop = loop_factory(scenario)
    try:
        result = loop.run(scenario.task)
    finally:
        audit_store = getattr(getattr(loop, "decider", None), "audit_store", None)
        close_audit = getattr(audit_store, "close", None)
        if callable(close_audit):
            close_audit()
    step_results: list[StepResult] = []

    for index, expected in enumerate(scenario.steps):
        if index >= len(result.steps):
            step_results.append(
                StepResult(
                    id=expected.id,
                    expected_decision=expected.expected_decision,
                    expected_risk_level=expected.expected_risk_level,
                    actual_decision=None,
                    actual_risk_level=None,
                    error="AgentGate returned no result for this step",
                )
            )
            continue

        actual = result.steps[index]
        error = actual.rejected_reason
        expected_proposal = ReplayPlanner([expected.action]).propose(scenario.task)
        if actual.proposal != expected_proposal:
            error = f"AgentGate proposal did not match the contract for step {expected.id!r}"
        decision = actual.decision
        step_results.append(
            StepResult(
                id=expected.id,
                expected_decision=expected.expected_decision,
                expected_risk_level=expected.expected_risk_level,
                actual_decision=decision.decision if decision else None,
                actual_risk_level=decision.risk_level if decision else None,
                error=error or ("AgentGate returned no decision" if decision is None else ""),
            )
        )

    extra_steps = len(result.steps) - len(scenario.steps)
    error = f"AgentGate returned {extra_steps} unexpected step(s)" if extra_steps > 0 else ""
    if getattr(result, "status", "") in {"failed", "max_steps_reached"}:
        error = f"AgentGate run ended with status {result.status!r}"
    return ScenarioResult(name=scenario.name, steps=step_results, error=error)


def run_scenarios(
    scenario_dir: Path = SCENARIO_DIR,
    loop_factory: LoopFactory = build_agentgate_loop,
) -> EvaluationReport:
    """Discover, validate, execute, and compare all scenarios."""
    paths = discover_scenarios(scenario_dir)
    if not paths:
        return EvaluationReport(
            [ScenarioResult(name="scenario_discovery", error=f"No scenarios found in {scenario_dir}")]
        )

    results: list[ScenarioResult] = []
    for path in paths:
        try:
            scenario = load_scenario(path)
            results.append(execute_scenario(scenario, loop_factory))
        except Exception as exc:
            results.append(ScenarioResult(name=path.stem, error=str(exc)))
    return EvaluationReport(results)


def format_report(report: EvaluationReport) -> str:
    """Render a human-readable report with scenario and step totals."""
    lines: list[str] = []
    passed_steps = 0
    total_steps = 0

    for scenario in report.scenarios:
        lines.append(f"Scenario: {scenario.name}")
        if scenario.error:
            lines.extend(["", f"Error: {scenario.error}", "", "Result: FAIL", ""])
        for index, step in enumerate(scenario.steps, start=1):
            total_steps += 1
            passed_steps += int(step.passed)
            lines.extend(
                [
                    "",
                    f"Step {index} ({step.id})",
                    "",
                    "Expected:",
                    f"decision: {step.expected_decision.value}",
                    f"risk_level: {step.expected_risk_level.value}",
                    "",
                    "Actual:",
                    f"decision: {step.actual_decision.value if step.actual_decision else 'NONE'}",
                    f"risk_level: {step.actual_risk_level.value if step.actual_risk_level else 'NONE'}",
                ]
            )
            if step.error:
                lines.append(f"error: {step.error}")
            lines.extend(["", f"Result: {'PASS' if step.passed else 'FAIL'}", ""])

    passed_scenarios = sum(scenario.passed for scenario in report.scenarios)
    total_scenarios = len(report.scenarios)
    lines.extend(
        [
            "Summary:",
            f"Passed: {passed_scenarios}/{total_scenarios}",
            f"Failed: {total_scenarios - passed_scenarios}/{total_scenarios}",
            f"Steps passed: {passed_steps}/{total_steps}",
            "",
            f"Exit code: {report.exit_code}",
        ]
    )
    return "\n".join(lines)


def _required_text(data: dict[str, Any], key: str, path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ScenarioValidationError(f"{path}: field {key!r} must be non-empty text")
    return value


def _validate_action_metadata(action: dict[str, Any], location: str) -> None:
    for key in ("domain", "target_system", "rationale"):
        if key in action and not isinstance(action[key], str):
            raise ScenarioValidationError(f"{location} field {key!r} must be text")
    confidence = action.get("confidence", 1.0)
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise ScenarioValidationError(
            f"{location} field 'confidence' must be a number between 0 and 1"
        )
    risk_hint = action.get("risk_hint", [])
    if not isinstance(risk_hint, list) or any(not isinstance(hint, str) for hint in risk_hint):
        raise ScenarioValidationError(f"{location} field 'risk_hint' must be a string list")
    if "rollback_available" in action and not isinstance(action["rollback_available"], bool):
        raise ScenarioValidationError(
            f"{location} field 'rollback_available' must be true or false"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AgentGate scenario regressions")
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        default=SCENARIO_DIR,
        help="directory containing scenario JSON files",
    )
    args = parser.parse_args(argv)
    report = run_scenarios(args.scenario_dir)
    print(format_report(report))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
