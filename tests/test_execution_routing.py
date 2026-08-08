from __future__ import annotations

import json
import unittest
from typing import Any, Mapping

from agentgate.executors import ExecutionResult, ExecutorRegistry
from agentgate.loop import AgentLoop
from agentgate.planner.base import Proposal
from agentgate.planner.replay import ReplayPlanner
from agentgate.router import DecisionRouter
from agentgate.sanitizer import sanitize
from agentgate.schemas import ActionRequest, Decision, DecisionResponse, RiskLevel
from agentgate.tools import ToolRegistry


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
        self.calls.append((action_type, dict(arguments)))
        return ExecutionResult(True, "success", "recorded", data={"ok": True})


def response(decision: Decision, sanitized_payload: str | None = None) -> DecisionResponse:
    return DecisionResponse(
        decision=decision,
        risk_level=RiskLevel.LOW,
        risk_score=0.0,
        sanitized_payload=sanitized_payload,
    )


class TestDecisionRouterExecution(unittest.TestCase):
    def setUp(self) -> None:
        self.executor = RecordingExecutor()
        self.registry = ExecutorRegistry()
        self.registry.register_action("FILE_READ", self.executor)
        self.registry.register_action("BROWSER_TYPE", self.executor)
        self.req = ActionRequest(action_type="FILE_READ", target="public/readme.txt")
        self.arguments = {"path": "public/readme.txt"}
        self.router = DecisionRouter(self.registry, execute=True)

    def test_allow_executes_exactly_once(self):
        outcome = self.router.route(self.req, response(Decision.ALLOW), self.arguments)
        self.assertEqual(outcome.status, "executed")
        self.assertEqual(len(self.executor.calls), 1)
        self.assertEqual(self.executor.calls[0][1], self.arguments)

    def test_block_executes_zero_times(self):
        outcome = self.router.route(self.req, response(Decision.BLOCK), self.arguments)
        self.assertEqual(outcome.status, "blocked")
        self.assertEqual(self.executor.calls, [])

    def test_need_approval_executes_zero_times(self):
        outcome = self.router.route(self.req, response(Decision.NEED_APPROVAL), self.arguments)
        self.assertEqual(outcome.status, "awaiting_approval")
        self.assertEqual(self.executor.calls, [])

    def test_ask_user_executes_zero_times(self):
        outcome = self.router.route(self.req, response(Decision.ASK_USER), self.arguments)
        self.assertEqual(outcome.status, "ask_user")
        self.assertEqual(self.executor.calls, [])

    def test_sanitize_executes_only_sanitized_value(self):
        req = ActionRequest(action_type="BROWSER_TYPE", target="1")
        original = {"element_id": "1", "value": "Contact john@example.com"}
        outcome = self.router.route(
            req,
            response(Decision.SANITIZE, "Contact [REDACTED_EMAIL]"),
            original,
        )
        self.assertEqual(outcome.status, "executed")
        self.assertEqual(self.executor.calls[0][1]["element_id"], "1")
        self.assertEqual(self.executor.calls[0][1]["value"], "Contact [REDACTED_EMAIL]")
        self.assertEqual(original["value"], "Contact john@example.com")

    def test_sanitize_replaces_api_body_without_losing_destination(self):
        self.registry.register_tool("github_create_issue_comment", self.executor)
        req = ActionRequest(
            action_type="API_CALL",
            tool_name="github_create_issue_comment",
            target_system="GitHub",
        )
        original = {
            "tool_name": "github_create_issue_comment",
            "owner": "octo",
            "repo": "demo",
            "issue_number": 7,
            "body": "Contact john@example.com",
        }
        self.router.route(
            req,
            response(Decision.SANITIZE, "Contact [REDACTED_EMAIL]"),
            original,
        )
        executed = self.executor.calls[0][1]
        self.assertEqual(executed["body"], "Contact [REDACTED_EMAIL]")
        self.assertEqual(executed["owner"], "octo")
        self.assertEqual(executed["issue_number"], 7)

    def test_api_sanitize_does_not_append_unrelated_context_to_body(self):
        self.registry.register_tool("github_create_issue_comment", self.executor)
        original = {
            "tool_name": "github_create_issue_comment",
            "owner": "octo",
            "repo": "demo",
            "issue_number": 7,
            "action_description": "APPENDED CONTROL TEXT",
            "body": "Contact john@example.com",
        }
        req = ActionRequest(
            action_type="API_CALL",
            tool_name="github_create_issue_comment",
            target="github_create_issue_comment",
            raw_payload="APPENDED CONTROL TEXT\nContact john@example.com",
        )
        self.router.route(
            req,
            response(Decision.SANITIZE, "APPENDED CONTROL TEXT\nContact [REDACTED_EMAIL]"),
            original,
        )
        self.assertEqual(self.executor.calls[0][1]["body"], "Contact [REDACTED_EMAIL]")

    def test_sanitize_does_not_click_when_content_cannot_be_replaced(self):
        self.registry.register_action("BROWSER_CLICK", self.executor)
        req = ActionRequest(
            action_type="BROWSER_CLICK",
            target="1",
            raw_payload="Contact john@example.com",
        )
        outcome = self.router.route(
            req,
            response(Decision.SANITIZE, "Contact [REDACTED_EMAIL]"),
            {"element_id": "1", "payload": "Contact john@example.com"},
        )
        self.assertEqual(outcome.status, "execution_failed")
        self.assertEqual(self.executor.calls, [])

    def test_changed_api_tool_cannot_reuse_allow_decision(self):
        self.registry.register_tool("github_create_issue", self.executor)
        req = ActionRequest(
            action_type="API_CALL",
            tool_name="github_read_repo",
            target="github_read_repo",
        )
        outcome = self.router.route(
            req,
            response(Decision.ALLOW),
            {"tool_name": "github_create_issue", "owner": "octo", "repo": "demo"},
        )
        self.assertEqual(outcome.status, "execution_failed")
        self.assertEqual(self.executor.calls, [])

    def test_structural_arguments_are_bound_to_evaluated_proposal(self):
        self.registry.register_tool("github_create_gist", self.executor)
        proposal = Proposal(
            action_type="API_CALL",
            arguments={
                "tool_name": "github_create_gist",
                "public": False,
                "files": {"demo.txt": "demo"},
            },
        )
        req = proposal.to_action_request(ToolRegistry())
        changed = dict(proposal.arguments)
        changed["public"] = True
        outcome = self.router.route(req, response(Decision.ALLOW), changed)
        self.assertEqual(outcome.status, "execution_failed")
        self.assertEqual(self.executor.calls, [])

    def test_dry_run_never_dispatches(self):
        outcome = DecisionRouter(self.registry).route(self.req, response(Decision.ALLOW))
        self.assertEqual(outcome.status, "would_execute")
        self.assertEqual(self.executor.calls, [])


class TestToolMetadataEnrichment(unittest.TestCase):
    def test_github_defaults_merge_without_losing_planner_hints(self):
        proposal = Proposal(
            action_type="API_CALL",
            arguments={"tool_name": "github_create_gist", "files": {"demo.py": "print('demo')"}},
            risk_hint=["payment_related"],
        )
        request = proposal.to_action_request(ToolRegistry())
        self.assertEqual(request.target_system, "GitHub")
        self.assertFalse(request.rollback_available)
        self.assertEqual(
            request.risk_hint,
            ["payment_related", "external_send", "source_code"],
        )
        self.assertNotIn("files", request.to_dict())

    def test_planner_cannot_weaken_registered_github_metadata(self):
        proposal = Proposal(
            action_type="API_CALL",
            arguments={"tool_name": "github_create_gist", "files": {"demo.py": "print('demo')"}},
            target_system="harmless-local-tool",
            rollback_available=True,
        )
        request = proposal.to_action_request(ToolRegistry())
        self.assertEqual(request.target_system, "GitHub")
        self.assertFalse(request.rollback_available)

    def test_executor_observation_sanitizer_redacts_private_key_header(self):
        self.assertEqual(
            sanitize("-----BEGIN RSA PRIVATE KEY-----"),
            "[REDACTED_PRIVATE_KEY]",
        )

    def test_executor_observation_sanitizer_covers_detected_token_formats(self):
        private_key = "-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----"
        jwt = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12
        text = " ".join(
            (
                "github_pat_" + "a" * 24,
                "xoxb-" + "a" * 12,
                jwt,
                private_key,
            )
        )
        redacted = sanitize(text)
        self.assertNotIn("github_pat_", redacted)
        self.assertNotIn("xoxb-", redacted)
        self.assertNotIn("eyJ", redacted)
        self.assertNotIn("key-material", redacted)
        self.assertEqual(sanitize("Call +1 (415) 555-0123"), "Call [REDACTED_PHONE]")


class TestLoopExecutionOrdering(unittest.TestCase):
    def test_guardrail_evaluates_before_original_arguments_reach_executor(self):
        events: list[str] = []

        class OrderedDecider:
            def evaluate(self, request: ActionRequest) -> DecisionResponse:
                events.append("guardrail")
                return response(Decision.ALLOW)

        class OrderedExecutor(RecordingExecutor):
            def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
                events.append("executor")
                return super().execute(action_type, arguments)

        executor = OrderedExecutor()
        registry = ExecutorRegistry()
        registry.register_action("FILE_READ", executor)
        loop = AgentLoop(
            ReplayPlanner([{"action_type": "FILE_READ", "arguments": {"path": "public/readme.txt"}}]),
            DecisionRouter(registry, execute=True),
            decider=OrderedDecider(),
        )
        loop.run("read a sandbox file")
        self.assertEqual(events, ["guardrail", "executor"])
        self.assertEqual(executor.calls[0][1]["path"], "public/readme.txt")

    def test_run_serialization_redacts_original_blocked_arguments(self):
        token = "ghp_" + "a" * 36
        loop = AgentLoop(
            ReplayPlanner(
                [
                    {
                        "action_type": "API_CALL",
                        "arguments": {
                            "tool_name": "github_create_issue_comment",
                            "owner": "octo",
                            "repo": "demo",
                            "issue_number": 1,
                            "body": f"do not send {token}",
                        },
                    }
                ]
            )
        )
        serialized = json.dumps(loop.run("unsafe send").to_dict())
        self.assertNotIn(token, serialized)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", serialized)

    def test_run_serialization_redacts_terminal_and_decision_text(self):
        token = "AKIAIOSFODNN7EXAMPLE"
        terminal = AgentLoop(
            ReplayPlanner([{"action_type": "DONE", "arguments": {"result_summary": token}}])
        ).run(f"task contains {token}")
        self.assertNotIn(token, json.dumps(terminal.to_dict()))

        blocked = AgentLoop(
            ReplayPlanner(
                [
                    {
                        "action_type": "API_CALL",
                        "arguments": {
                            "tool_name": "github_create_issue_comment",
                            "body": f"source snippet {token}",
                        },
                    }
                ]
            )
        ).run("block source secret")
        self.assertNotIn(token, json.dumps(blocked.to_dict()))


if __name__ == "__main__":
    unittest.main()
