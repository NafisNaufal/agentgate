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
from agentgate.schemas import ACTION_TYPES, ActionRequest, Decision, RiskLevel  # noqa: E402

_APPROVAL_DECISIONS = {"NEED_APPROVAL", "ASK_USER"}
_DECISIONS = {decision.value for decision in Decision}
_RISK_LEVELS = {level.value for level in RiskLevel}
_EXPECTATION_SOURCES = {"da_approved", "inferred"}


def evaluate_cases(cases: list[dict[str, Any]], engine: Any) -> dict[str, Any]:
    """Evaluate cases through an injected engine and return a JSON-safe report."""
    results: list[dict[str, Any]] = []
    for case in cases:
        started = time.perf_counter()
        evaluation_started: float | None = None
        source = case.get("expectation_source", "<missing>")
        try:
            _validate_case(case)
            request = ActionRequest(**case["action_request"])
            evaluation_started = time.perf_counter()
            response = engine.evaluate(request)
            elapsed_ms = (time.perf_counter() - evaluation_started) * 1000
            actual_decision = response.decision.value
            actual_risk = response.risk_level.value
            expected_decision = case["expected_decision"]
            expected_risk = case["expected_risk_level"]
            decision_match = actual_decision == expected_decision
            risk_match = actual_risk == expected_risk
            case_result = {
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
            runtime_error = response.evaluation_error
            if runtime_error:
                case_result["runtime_error"] = runtime_error
            results.append(case_result)
        except Exception as exc:
            error_result = {
                "id": case.get("id", "<unknown>"),
                "title": case.get("title", "<unknown>"),
                "expectation_source": source,
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_ms": round(
                    (time.perf_counter() - (evaluation_started or started)) * 1000, 3
                ),
            }
            for key in (
                "expected_decision",
                "expected_risk_level",
                "expected_entity_kinds",
            ):
                if key in case:
                    error_result[key] = case[key]
            results.append(error_result)

    completed = [result for result in results if "error" not in result]
    errors = [
        result for result in results if "error" in result or "runtime_error" in result
    ]
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

    audit_metric = _audit_completeness(engine, results)
    metrics = _complete_metrics(results, len(results), all_policy_ids, audit_metric)
    approved_results = sources["da_approved"]
    headline_metrics = _complete_metrics(
        approved_results, len(approved_results), all_policy_ids, audit_metric
    )
    source_metrics = {
        source: {
            "total": len(source_results),
            "metrics": _complete_metrics(
                source_results, len(source_results), all_policy_ids, audit_metric
            ),
        }
        for source, source_results in sources.items()
        if source_results
    }

    return {
        "ok": bool(results) and not errors and not mismatches and "error" not in audit_metric,
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
    required = (
        "id",
        "title",
        "expectation_source",
        "expected_decision",
        "expected_risk_level",
        "action_request",
    )
    missing = [key for key in required if key not in case]
    if missing:
        raise ValueError(f"case is missing required fields: {', '.join(missing)}")
    source = case["expectation_source"]
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
    action_type = case["action_request"].get("action_type")
    if action_type not in ACTION_TYPES:
        raise ValueError(f"unknown action_type: {action_type!r}")


def _validate_dataset(cases: list[dict[str, Any]]) -> None:
    if len(cases) != 26:
        raise ValueError(f"DA evaluation set must contain 26 cases, found {len(cases)}")
    ids = [case.get("id") for case in cases]
    if len(set(ids)) != len(ids):
        raise ValueError("DA evaluation set contains duplicate case ids")
    for case in cases:
        _validate_case(case)
    source_counts = {
        source: sum(case["expectation_source"] == source for case in cases)
        for source in _EXPECTATION_SOURCES
    }
    if source_counts != {"da_approved": 19, "inferred": 7}:
        raise ValueError(
            "DA evaluation set must contain 19 da_approved and 7 inferred cases; "
            f"found {source_counts}"
        )


def _metrics_for(results: list[dict[str, Any]], total: int) -> dict[str, Any]:
    completed = [result for result in results if "error" not in result]
    expected = [result for result in results if "expected_decision" in result]
    unsafe = [result for result in expected if result["expected_decision"] != "ALLOW"]
    sensitive = [result for result in expected if result.get("expected_entity_kinds")]
    approval = [
        result
        for result in expected
        if result["expected_decision"] in _APPROVAL_DECISIONS
    ]
    benign = [result for result in expected if result["expected_decision"] == "ALLOW"]

    expected_entity_count = sum(
        len(set(result["expected_entity_kinds"])) for result in sensitive
    )
    detected_entity_count = sum(
            len(
                set(result["expected_entity_kinds"])
                & set(result.get("sensitive_entity_kinds", []))
        )
        for result in sensitive
    )
    by_entity_kind: dict[str, dict[str, Any]] = {}
    for kind in sorted(
        {kind for result in sensitive for kind in result["expected_entity_kinds"]}
    ):
        expected = [result for result in sensitive if kind in result["expected_entity_kinds"]]
        detected = [
            result
            for result in expected
            if kind in result.get("sensitive_entity_kinds", [])
        ]
        by_entity_kind[kind] = _ratio(len(detected), len(expected))

    recall = _ratio(detected_entity_count, expected_entity_count)
    recall["by_entity_kind"] = by_entity_kind
    return {
        "action_evaluation_completion_rate": _ratio(len(completed), total),
        "unsafe_auto_allow_rate": _ratio(
            sum(result.get("actual_decision") == "ALLOW" for result in unsafe),
            len(unsafe),
        ),
        "sensitive_data_detection_recall": recall,
        "approval_routing_accuracy": _ratio(
            sum(result.get("actual_decision") in _APPROVAL_DECISIONS for result in approval),
            len(approval),
        ),
        "false_block_rate": _ratio(
            sum(result.get("actual_decision") == "BLOCK" for result in benign),
            len(benign),
        ),
    }


def _complete_metrics(
    results: list[dict[str, Any]],
    total: int,
    all_policy_ids: set[str],
    audit_metric: dict[str, Any],
) -> dict[str, Any]:
    metrics = _metrics_for(results, total)
    metrics.update(
        {
            "policy_coverage": _policy_coverage(results, all_policy_ids),
            "guardrail_evaluation_latency_ms": _latency_metrics(
                [result for result in results if "error" not in result]
            ),
            "audit_completeness": audit_metric,
            "task_success": None,
        }
    )
    return metrics


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


def _policy_coverage(results: list[dict[str, Any]], all_policy_ids: set[str]) -> dict[str, Any]:
    triggered = {
        policy_id
        for result in results
        if "error" not in result
        for policy_id in result["triggered_policies"]
    }
    return _ratio(len(triggered & all_policy_ids), len(all_policy_ids))


def _audit_completeness(engine: Any, results: list[dict[str, Any]]) -> dict[str, Any]:
    get_record = getattr(getattr(engine, "audit_store", None), "get", None)
    if not callable(get_record):
        return {
            "value": None,
            "scope": "selected_run",
            "error": "audit store does not expose get()",
        }
    try:
        complete = sum(
            1
            for result in results
            if _audit_record_complete(get_record(result.get("audit_id", "")))
        )
        return {
            "value": round(complete / len(results), 4) if results else 1.0,
            "numerator": complete,
            "denominator": len(results),
            "scope": "selected_run",
        }
    except Exception as exc:
        return {
            "value": None,
            "scope": "selected_run",
            "error": f"{type(exc).__name__}: {exc}",
        }


def _audit_record_complete(record: Any) -> bool:
    if record is None:
        return False
    if isinstance(record, dict):
        request = record.get("request")
        response = record.get("response")
        status = record.get("execution_status")
        timestamp = record.get("timestamp")
    else:
        request = getattr(record, "request", None)
        response = getattr(record, "response", None)
        status = getattr(record, "execution_status", None)
        timestamp = getattr(record, "timestamp", None)
    if isinstance(response, dict):
        decision = response.get("decision")
        reasons = response.get("reasons")
    else:
        decision = getattr(response, "decision", None)
        reasons = getattr(response, "reasons", None)
    return (
        request is not None
        and decision is not None
        and reasons is not None
        and bool(status)
        and timestamp is not None
    )


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
        _validate_dataset(cases)
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
    source = case["expectation_source"]
    if source == "da_approved":
        metrics = report["headline_metrics"]
        heading = "Headline metrics (DA-approved)"
    else:
        metrics = report["metrics_by_expectation_source"][source]["metrics"]
        heading = "Provisional metrics (inferred)"
    _print_metric_summary(metrics, heading=heading)


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
    print("Expectation sources:")
    for source, count in summary["expectation_sources"].items():
        print(f"  {source}: {count}")
    _print_metric_summary(
        report["headline_metrics"], heading="Headline metrics (DA-approved)"
    )
    if "inferred" in report["metrics_by_expectation_source"]:
        _print_metric_summary(
            report["metrics_by_expectation_source"]["inferred"]["metrics"],
            heading="Provisional metrics (inferred)",
        )


def _print_metric_summary(metrics: dict[str, Any], *, heading: str = "Metrics") -> None:
    print(f"{heading}:")
    for name, metric in metrics.items():
        if name == "task_success":
            print(f"  {name}: N/A")
        elif name == "guardrail_evaluation_latency_ms":
            print(f"  {name}: P50={metric['p50_ms']} ms, P95={metric['p95_ms']} ms")
        elif name == "sensitive_data_detection_recall":
            print(f"  {name}: {_format_value(metric['value'])}")
            for kind, kind_metric in metric["by_entity_kind"].items():
                print(f"    {kind}: {_format_value(kind_metric['value'])}")
        elif isinstance(metric, dict) and "value" in metric:
            print(f"  {name}: {_format_value(metric['value'])}")


def _format_value(value: Any) -> str:
    return "N/A" if value is None else f"{value:.2%}"


if __name__ == "__main__":
    raise SystemExit(main())
