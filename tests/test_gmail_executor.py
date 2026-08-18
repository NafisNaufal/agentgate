"""Gmail executor tests. HTTP is mocked; nothing here contacts Google."""

from __future__ import annotations

import json
import unittest
from typing import Any
from unittest.mock import patch

from agentgate.executors.gmail import GmailExecutor
from agentgate.executors.google_auth import AuthError
from agentgate.schemas import ActionRequest
from agentgate.tool_specs import GMAIL_TOOL_SPECS
from agentgate.tools import ToolRegistry

TOKEN = "ya29.a0AfH6SMBsecrettokenvalue"


class FakeResponse:
    def __init__(self, payload: Any, status: int = 200) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self, size: int = -1) -> bytes:
        body, self._body = self._body, b""
        return body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class RecordingOpener:
    """Captures the requests the executor makes and replays queued responses."""

    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: float | None = None) -> Any:
        self.requests.append(request)
        return self.responses.pop(0)

    @property
    def last_body(self) -> dict[str, Any]:
        return json.loads(self.requests[-1].data.decode("utf-8"))


def executor(*responses: Any) -> tuple[GmailExecutor, RecordingOpener]:
    opener = RecordingOpener(*responses)
    return GmailExecutor(opener=opener, token_provider=lambda: TOKEN), opener


class TestGmailSearch(unittest.TestCase):
    def test_search_returns_message_ids(self):
        gmail, opener = executor(
            FakeResponse({"messages": [{"id": "a1"}, {"id": "a2"}], "resultSizeEstimate": 2})
        )
        result = gmail.execute("API_CALL", {"tool_name": "gmail_search", "q": "older_than:30d"})
        self.assertTrue(result.success)
        self.assertEqual(result.data["message_ids"], ["a1", "a2"])
        self.assertIn("q=older_than", opener.requests[0].full_url)

    def test_search_requires_a_query(self):
        gmail, _ = executor()
        result = gmail.execute("API_CALL", {"tool_name": "gmail_search"})
        self.assertFalse(result.success)
        self.assertEqual(result.status, "invalid_arguments")

    def test_max_results_is_bounded(self):
        gmail, _ = executor()
        result = gmail.execute(
            "API_CALL", {"tool_name": "gmail_search", "q": "x", "max_results": 5000}
        )
        self.assertEqual(result.status, "invalid_arguments")


class TestGmailArchive(unittest.TestCase):
    def test_archive_uses_one_batch_request(self):
        ids = [f"id{n}" for n in range(320)]
        gmail, opener = executor(FakeResponse({}))
        result = gmail.execute(
            "API_CALL", {"tool_name": "gmail_archive", "message_ids": ids}
        )
        self.assertTrue(result.success)
        # 320 messages must not become 320 HTTP requests.
        self.assertEqual(len(opener.requests), 1)
        self.assertIn("batchModify", opener.requests[0].full_url)
        self.assertEqual(opener.last_body["removeLabelIds"], ["INBOX"])
        self.assertEqual(len(opener.last_body["ids"]), 320)

    def test_archive_rejects_empty_ids(self):
        gmail, _ = executor()
        result = gmail.execute("API_CALL", {"tool_name": "gmail_archive", "message_ids": []})
        self.assertEqual(result.status, "invalid_arguments")

    def test_archive_rejects_oversized_batch(self):
        gmail, _ = executor()
        result = gmail.execute(
            "API_CALL", {"tool_name": "gmail_archive", "message_ids": [f"i{n}" for n in range(1001)]}
        )
        self.assertEqual(result.status, "invalid_arguments")


class TestGmailSend(unittest.TestCase):
    def test_send_builds_a_valid_message(self):
        gmail, opener = executor(FakeResponse({"id": "m1", "threadId": "t1"}))
        result = gmail.execute(
            "API_CALL",
            {
                "tool_name": "gmail_send",
                "to": "customer@example.com",
                "subject": "Booking confirmed",
                "body": "Your booking is confirmed.",
            },
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data["id"], "m1")
        from base64 import urlsafe_b64decode

        raw = urlsafe_b64decode(opener.last_body["raw"]).decode()
        self.assertIn("To: customer@example.com", raw)
        self.assertIn("Subject: Booking confirmed", raw)

    def test_header_injection_via_subject_is_rejected(self):
        gmail, opener = executor(FakeResponse({}))
        result = gmail.execute(
            "API_CALL",
            {
                "tool_name": "gmail_send",
                "to": "a@example.com",
                "subject": "Hi\nBcc: attacker@evil.com",
                "body": "text",
            },
        )
        self.assertEqual(result.status, "invalid_arguments")
        self.assertEqual(opener.requests, [])

    def test_header_injection_via_recipient_is_rejected(self):
        gmail, opener = executor(FakeResponse({}))
        result = gmail.execute(
            "API_CALL",
            {
                "tool_name": "gmail_send",
                "to": "a@example.com\nBcc: attacker@evil.com",
                "subject": "Hi",
                "body": "text",
            },
        )
        self.assertEqual(result.status, "invalid_arguments")
        self.assertEqual(opener.requests, [])

    def test_invalid_recipient_is_rejected(self):
        gmail, _ = executor(FakeResponse({}))
        result = gmail.execute(
            "API_CALL",
            {"tool_name": "gmail_send", "to": "not-an-address", "subject": "s", "body": "b"},
        )
        self.assertEqual(result.status, "invalid_arguments")


class TestGmailSafety(unittest.TestCase):
    def test_unsupported_tool_is_refused(self):
        gmail, opener = executor()
        result = gmail.execute("API_CALL", {"tool_name": "gmail_delete_forever"})
        self.assertEqual(result.status, "unsupported_action")
        self.assertEqual(opener.requests, [])

    def test_browser_action_is_refused(self):
        gmail, _ = executor()
        self.assertEqual(
            gmail.execute("BROWSER_CLICK", {"element_id": "1"}).status, "unsupported_action"
        )

    def test_access_token_never_appears_in_output(self):
        gmail, _ = executor(FakeResponse({"id": TOKEN, "threadId": f"leaked {TOKEN}"}))
        result = gmail.execute(
            "API_CALL",
            {"tool_name": "gmail_send", "to": "a@example.com", "subject": "s", "body": "b"},
        )
        rendered = json.dumps(result.to_dict())
        self.assertNotIn(TOKEN, rendered)
        self.assertIn("REDACTED_GOOGLE_TOKEN", rendered)

    def test_missing_credentials_are_reported_not_raised(self):
        def no_token() -> str:
            raise AuthError("Missing Google OAuth environment variables: GOOGLE_CLIENT_ID")

        gmail = GmailExecutor(opener=RecordingOpener(), token_provider=no_token)
        result = gmail.execute("API_CALL", {"tool_name": "gmail_search", "q": "x"})
        self.assertFalse(result.success)
        self.assertEqual(result.status, "configuration_error")

    def test_token_is_cleared_after_execution(self):
        gmail, _ = executor(FakeResponse({"messages": []}))
        gmail.execute("API_CALL", {"tool_name": "gmail_search", "q": "x"})
        self.assertEqual(gmail._token, "")


class TestGmailToolMetadata(unittest.TestCase):
    def test_send_declares_every_content_field(self):
        # The bug this guards: without content_fields the ActionRequest payload is
        # empty and the guardrail evaluates an outbound email with no body.
        spec = ToolRegistry().get("gmail_send")
        self.assertEqual(spec.content_fields, ("to", "subject", "body", "cc", "bcc"))
        self.assertFalse(spec.rollback_available)
        self.assertIn("external_send", spec.default_risk_hints)

    def test_send_payload_reaches_the_guardrail(self):
        from agentgate.planner.base import Proposal

        request = Proposal(
            action_type="API_CALL",
            arguments={
                "tool_name": "gmail_send",
                "to": "customer@example.com",
                "subject": "Invoice",
                "body": "Pay at http://pay.example.com/invoice",
            },
        ).to_action_request(ToolRegistry())
        self.assertIn("customer@example.com", request.scan_text)
        self.assertIn("pay.example.com", request.scan_text)
        self.assertEqual(request.target_system, "Gmail")
        self.assertFalse(request.rollback_available)

    def test_read_only_tools_are_not_flagged_as_external_send(self):
        registry = ToolRegistry()
        for name in ("gmail_search", "gmail_archive"):
            self.assertEqual(registry.get(name).default_risk_hints, ())
            self.assertTrue(registry.get(name).rollback_available)

    def test_every_gmail_spec_is_registered(self):
        registry = ToolRegistry()
        for spec in GMAIL_TOOL_SPECS:
            self.assertTrue(registry.is_registered(spec.name))


if __name__ == "__main__":
    unittest.main()
