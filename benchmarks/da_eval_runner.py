"""Run the DA-authored evaluation set through the production DecisionEngine.

The runner keeps the evaluation contract independent from the detector
implementation. It compares both decision and risk level, reports PRD metrics,
and exits non-zero when the selected cases do not match their expectations.

Usage:
  python3 benchmarks/da_eval_runner.py
  python3 benchmarks/da_eval_runner.py --case RSV-04
  python3 benchmarks/da_eval_runner.py --case RSV --case DATA-0 --json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentgate.audit import AuditUnavailable  # noqa: E402
from agentgate.decision import DecisionEngine  # noqa: E402
from agentgate.schemas import ActionRequest  # noqa: E402

_APPROVAL_DECISIONS = {"NEED_APPROVAL", "ASK_USER"}
_DECISIONS = {"ALLOW", "SANITIZE", "ASK_USER", "NEED_APPROVAL", "BLOCK"}
_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_EXPECTATION_SOURCES = {"da_approved", "inferred"}


def evaluate_cases(cases: list[dict[str, Any]], engine: Any) -> dict[str, Any]:
    """Evaluate cases through an injected engine and return a JSON-safe report."""
    results: list[dict[str, Any]] = []
    for case in cases:
        started = time.perf_counter()
        source = case.get("expectation_source", "da_approved")
        try:
            _validate_case(case)
            request = ActionRequest(**case["action_request"])
            response = engine.evaluate(request)
            elapsed_ms = (time.perf_counter() - started) * 1000
            actual_decision = response.decision.value
            actual_risk = response.risk_level.value
            expected_decision = case["expected_decision"]
            expected_risk = case["expected_risk_level"]
            decision_match = actual_decision == expected_decision
            risk_match = actual_risk == expected_risk
            results.append(
                {
                    "id": case["id"],
                    "title": case["title"],
                    "user_instruction": case.get("user_instruction", ""),
                    "expectation_source": source,
                    "expected_decision": expected_decision,
                    "expected_risk_level": expected_risk,
                    "expected_entity_kinds": list(case.get("expected_entity_kinds", [])),
                    "actual_decision": actual_decision,
                    "actual_risk_level": actual_risk,
                    "risk_score": response.risk_score,
                    "decision_match": decision_match,
                    "risk_match": risk_match,
                    "match": decision_match and risk_match,
                    "elapsed_ms": round(elapsed_ms, 3),
                    "triggered_policies": list(response.triggered_policies),
                    "sensitive_entities": [
                        entity.to_dict() for entity in response.sensitive_entities
                    ],
                    "sensitive_entity_kinds": sorted(
                        {entity.kind for entity in response.sensitive_entities}
                    ),
                    "sanitized_payload": response.sanitized_payload,
                    "reasons": list(response.reasons),
                    "audit_id": response.audit_id,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "id": case.get("id", "<unknown>"),
                    "title": case.get("title", "<unknown>"),
                    "expectation_source": source,
                    "error": f"{type(exc).__name__}: {exc}",
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                }
            )

    completed = [result for result in results if "error" not in result]
    errors = [result for result in results if "error" in result]
    mismatches = [result for result in completed if not result["match"]]
    sources = {
        source: [result for result in results if result["expectation_source"] == source]
        for source in _EXPECTATION_SOURCES
    }
    all_policy_ids = _policy_ids(engine)
    triggered_policy_ids = sorted(
        {
            policy_id
            for result in completed
            for policy_id in result["triggered_policies"]
        }
    )

    metrics = _metrics_for(results, len(results))
    metrics.update(
        {
            "policy_coverage": _ratio(len(set(triggered_policy_ids) & all_policy_ids), len(all_policy_ids)),
            "guardrail_evaluation_latency_ms": _latency_metrics(completed),
            "audit_completeness": _audit_completeness(engine),
            "task_success": None,
        }
    )
    approved_results = sources["da_approved"]
    headline_metrics = _metrics_for(approved_results, len(approved_results))
    source_metrics = {
        source: {
            "total": len(source_results),
            "metrics": _metrics_for(source_results, len(source_results)),
        }
        for source, source_results in sources.items()
        if source_results
    }

    return {
        "ok": bool(results) and not errors and not mismatches,
        "summary": {
            "total": len(results),
            "completed": len(completed),
            "matched": len(completed) - len(mismatches),
            "mismatches": len(mismatches),
            "errors": len(errors),
            "expectation_sources": {
                source: len(source_results)
                for source, source_results in sources.items()
                if source_results
            },
        },
        "metrics": metrics,
        "headline_metrics": headline_metrics,
        "metrics_by_expectation_source": source_metrics,
        "policy_ids": {
            "loaded": sorted(all_policy_ids),
            "triggered": triggered_policy_ids,
        },
        "cases": results,
    }


def _validate_case(case: dict[str, Any]) -> None:
    required = ("id", "title", "expected_decision", "expected_risk_level", "action_request")
    missing = [key for key in required if key not in case]
    if missing:
        raise ValueError(f"case is missing required fields: {', '.join(missing)}")
    source = case.get("expectation_source", "da_approved")
    if source not in _EXPECTATION_SOURCES:
        raise ValueError(f"expectation_source must be one of {sorted(_EXPECTATION_SOURCES)}")
    if case["expected_decision"] not in _DECISIONS:
        raise ValueError(f"unknown expected_decision: {case['expected_decision']!r}")
    if case["expected_risk_level"] not in _RISK_LEVELS:
        raise ValueError(f"unknown expected_risk_level: {case['expected_risk_level']!r}")
    entity_kinds = case.get("expected_entity_kinds", [])
    if not isinstance(entity_kinds, list) or any(not isinstance(kind, str) for kind in entity_kinds):
        raise ValueError("expected_entity_kinds must be a list of strings")
    if not isinstance(case["action_request"], dict):
        raise ValueError("action_request must be an object")


def _metrics_for(results: list[dict[str, Any]], total: int) -> dict[str, Any]:
    completed = [result for result in results if "error" not in result]
    unsafe = [result for result in completed if result["expected_decision"] != "ALLOW"]
    sensitive = [
        result for result in completed if result.get("expected_entity_kinds")
    ]
    approval = [
        result
        for result in completed
        if result["expected_decision"] in _APPROVAL_DECISIONS
    ]
    benign = [result for result in completed if result["expected_decision"] == "ALLOW"]

    expected_entity_count = sum(
        len(set(result["expected_entity_kinds"])) for result in sensitive
    )
    detected_entity_count = sum(
        len(
            set(result["expected_entity_kinds"])
            & set(result["sensitive_entity_kinds"])
        )
        for result in sensitive
    )
    by_entity_kind: dict[str, dict[str, Any]] = {}
    for kind in sorted(
        {kind for result in sensitive for kind in result["expected_entity_kinds"]}
    ):
        expected = [result for result in sensitive if kind in result["expected_entity_kinds"]]
        detected = [result for result in expected if kind in result["sensitive_entity_kinds"]]
        by_entity_kind[kind] = _ratio(len(detected), len(expected))

    recall = _ratio(detected_entity_count, expected_entity_count)
    recall["by_entity_kind"] = by_entity_kind
    return {
        "action_evaluation_completion_rate": _ratio(len(completed), total),
        "unsafe_auto_allow_rate": _ratio(
            sum(result["actual_decision"] == "ALLOW" for result in unsafe), len(unsafe)
        ),
        "sensitive_data_detection_recall": recall,
        "approval_routing_accuracy": _ratio(
            sum(result["actual_decision"] in _APPROVAL_DECISIONS for result in approval),
            len(approval),
        ),
        "false_block_rate": _ratio(
            sum(result["actual_decision"] == "BLOCK" for result in benign), len(benign)
        ),
    }


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "value": round(numerator / denominator, 4) if denominator else None,
        "numerator": numerator,
        "denominator": denominator,
    }


def _latency_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    values = sorted(result["elapsed_ms"] for result in results)
    return {
        "count": len(values),
        "p50_ms": _nearest_rank(values, 0.50),
        "p95_ms": _nearest_rank(values, 0.95),
    }


def _nearest_rank(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    index = max(0, math.ceil(percentile * len(values)) - 1)
    return values[index]


def _policy_ids(engine: Any) -> set[str]:
    rules = getattr(getattr(engine, "policy_engine", None), "rules", [])
    return {rule["id"] for rule in rules if isinstance(rule, dict) and "id" in rule}


def _audit_completeness(engine: Any) -> dict[str, Any]:
    completeness = getattr(getattr(engine, "audit_store", None), "completeness", None)
    if not callable(completeness):
        return {"value": None, "error": "audit store does not expose completeness()"}
    try:
        return {"value": completeness()}
    except Exception as exc:
        return {"value": None, "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        action="append",
        default=None,
        help="only run cases whose id contains this substring (repeatable); omit to run all",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the complete machine-readable report"
    )
    args = parser.parse_args()

    try:
        data = json.loads((ROOT / "benchmarks" / "data" / "da_eval_set.json").read_text())
        cases = data["cases"]
        if args.case:
            cases = [case for case in cases if any(needle in case["id"] for needle in args.case)]
            if not cases:
                message = {
                    "error": f"No case id contains any of {args.case}",
                    "available_ids": [case["id"] for case in data["cases"]],
                }
                print(json.dumps(message, indent=2) if args.json else message["error"])
                if not args.json:
                    print("Available ids:")
                    print(", ".join(message["available_ids"]))
                return 1
        engine = DecisionEngine()
    except Exception as exc:
        message = {"error": f"{type(exc).__name__}: {exc}"}
        print(json.dumps(message, indent=2) if args.json else message["error"])
        return 1

    report = evaluate_cases(cases, engine)
    if args.json:
        print(json.dumps(report, indent=2))
    elif args.case and len(cases) == 1:
        _print_single_case(report["cases"][0], report)
    else:
        _print_table(report)
    return 0 if report["ok"] else 1


def _print_single_case(case: dict[str, Any], report: dict[str, Any]) -> None:
    print(f"{case['id']} - {case['title']}")
    if "error" in case:
        print(f"  ERROR: {case['error']}")
        return
    print(f"  user instruction: {case['user_instruction']}")
    print(f"  expected: {case['expected_decision']} ({case['expected_risk_level']})")
    print(
        f"  actual:   {case['actual_decision']} ({case['actual_risk_level']}, "
        f"score={case['risk_score']})"
    )
    print(f"  {'MATCH' if case['match'] else 'MISMATCH'}")
    print(f"  reasons: {case['reasons']}")
    if case["triggered_policies"]:
        print(f"  triggered_policies: {case['triggered_policies']}")
    if case["sanitized_payload"]:
        print(f"  sanitized_payload: {case['sanitized_payload']!r}")
    _print_metric_summary(report["metrics"])


def _print_table(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(
        f"DA test scenarios: {summary['matched']}/{summary['total']} match expected "
        "decision and risk\n"
    )
    header = (
        f"{'ID':<10} {'Expected':<15} {'Actual':<15} {'Exp.Risk':<10} "
        f"{'Act.Risk':<10} {'Match':<8} Title"
    )
    print(header)
    print("-" * len(header))
    for case in report["cases"]:
        if "error" in case:
            print(f"{case['id']:<10} ERROR    {case['error']}")
            continue
        mark = "OK" if case["match"] else "MISMATCH"
        print(
            f"{case['id']:<10} {case['expected_decision']:<15} "
            f"{case['actual_decision']:<15} {case['expected_risk_level']:<10} "
            f"{case['actual_risk_level']:<10} {mark:<8} {case['title']}"
        )
    print()
    _print_metric_summary(report["metrics"])


def _print_metric_summary(metrics: dict[str, Any]) -> None:
    print("Metrics:")
    for name, metric in metrics.items():
        if name == "task_success":
            print(f"  {name}: N/A")
        elif name == "guardrail_evaluation_latency_ms":
            print(f"  {name}: P50={metric['p50_ms']} ms, P95={metric['p95_ms']} ms")
        elif name == "sensitive_data_detection_recall":
            print(f"  {name}: {_format_value(metric['value'])}")
        elif isinstance(metric, dict) and "value" in metric:
            print(f"  {name}: {_format_value(metric['value'])}")


def _format_value(value: Any) -> str:
    return "N/A" if value is None else f"{value:.2%}"


if __name__ == "__main__":
    raise SystemExit(main())
