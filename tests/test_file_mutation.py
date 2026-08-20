"""Regressions for the two holes the DA eval set exposed (DATA-06 and DATA-07).

Both were found by running DA's independently-authored cases against a live model, and
neither could have been caught by the scenarios, because no scenario proposed a file
mutation and none claimed rollback on a destructive action.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from agentgate.action_space import ActionSpaceError, validate_proposal
from agentgate.decision import DecisionEngine
from agentgate.planner.base import Proposal
from agentgate.schemas import ACTION_TYPES, ActionRequest, Decision
from tests.fake_audit import audit_patch
from tests.fake_llm import fake_chat_json

_AUDIT = None


def setUpModule():
    global _AUDIT
    _AUDIT = audit_patch()
    _AUDIT.start()


def tearDownModule():
    _AUDIT.stop()


class TestDestructiveActionAlwaysReachesAHuman(unittest.TestCase):
    """DATA-07: a destructive action must not be allowed just because the planner
    claims it is reversible.

    Before the fix, the intent detector flagged 'Destructive verb detected' and the
    engine still returned ALLOW: global.destructive_no_rollback carries
    requires_no_rollback, so a planner claiming rollback_available=True disabled the
    only rule covering it, and 0.5 lands in MEDIUM which maps to ALLOW.
    """

    def setUp(self):
        self.llm = patch("agentgate.detectors.llm_client.chat_json", side_effect=fake_chat_json)
        self.llm.start()
        self.engine = DecisionEngine()

    def tearDown(self):
        self.llm.stop()

    def _delete(self, **overrides) -> ActionRequest:
        fields = {
            "action_type": "FILE_READ",
            "domain": "code_security",
            "target_system": "local file",
            "payload_summary": "delete local project file, irreversible without version control",
            "rollback_available": False,
            "confidence": 0.89,
        }
        fields.update(overrides)
        return ActionRequest(**fields)

    def test_destructive_with_claimed_rollback_still_needs_approval(self):
        decision = self.engine.evaluate(self._delete(rollback_available=True))
        self.assertEqual(decision.decision, Decision.NEED_APPROVAL)
        self.assertIn("global.destructive_action", decision.triggered_policies)

    def test_destructive_without_rollback_still_needs_approval(self):
        decision = self.engine.evaluate(self._delete(rollback_available=False))
        self.assertEqual(decision.decision, Decision.NEED_APPROVAL)
        self.assertIn("global.destructive_no_rollback", decision.triggered_policies)

    def test_planner_cannot_suppress_it_by_dropping_the_risk_hint(self):
        # The intent detector re-adds the tag, so the policy still matches.
        decision = self.engine.evaluate(self._delete(risk_hint=[], rollback_available=True))
        self.assertEqual(decision.decision, Decision.NEED_APPROVAL)

    def test_a_non_destructive_action_is_unaffected(self):
        decision = self.engine.evaluate(
            ActionRequest(action_type="FILE_READ", payload_summary="read the project readme")
        )
        self.assertEqual(decision.decision, Decision.ALLOW)


class TestFileMutationVocabulary(unittest.TestCase):
    """DATA-06: a file write was expressible only as FILE_READ, so no policy matched."""

    def setUp(self):
        self.llm = patch("agentgate.detectors.llm_client.chat_json", side_effect=fake_chat_json)
        self.llm.start()
        self.engine = DecisionEngine()

    def tearDown(self):
        self.llm.stop()

    def test_write_and_delete_are_registered_verbs(self):
        self.assertIn("FILE_WRITE", ACTION_TYPES)
        self.assertIn("FILE_DELETE", ACTION_TYPES)

    def test_write_requires_path_and_content(self):
        with self.assertRaises(ActionSpaceError):
            validate_proposal("FILE_WRITE", {"path": "config.py"})
        validate_proposal("FILE_WRITE", {"path": "config.py", "content": "x = 1"})

    def test_delete_requires_a_path(self):
        with self.assertRaises(ActionSpaceError):
            validate_proposal("FILE_DELETE", {})
        validate_proposal("FILE_DELETE", {"path": "build/old.o"})

    def test_write_needs_approval_instead_of_being_allowed(self):
        decision = self.engine.evaluate(
            ActionRequest(
                action_type="FILE_WRITE",
                domain="code_security",
                target_system="local file",
                target="config.py",
                payload_summary="write modified content to local project file",
            )
        )
        self.assertEqual(decision.decision, Decision.NEED_APPROVAL)
        self.assertIn("code.local_file_write", decision.triggered_policies)

    def test_delete_needs_approval(self):
        decision = self.engine.evaluate(
            ActionRequest(
                action_type="FILE_DELETE",
                domain="code_security",
                target_system="local file",
                target="build/old.o",
            )
        )
        self.assertEqual(decision.decision, Decision.NEED_APPROVAL)
        self.assertIn("code.local_file_delete", decision.triggered_policies)

    def test_written_content_is_scanned_for_secrets(self):
        # Without FILE_WRITE in _payload_text's key list the content would be invisible,
        # exactly the bug the Gmail connector had with missing content_fields.
        token = "ghp_" + "a" * 36
        request = Proposal(
            action_type="FILE_WRITE",
            arguments={"path": "app/config.py", "content": f"GITHUB_TOKEN = {token}"},
            domain="code_security",
        ).to_action_request()
        self.assertIn(token, request.scan_text)
        decision = self.engine.evaluate(request)
        self.assertIn(decision.decision, {Decision.BLOCK, Decision.SANITIZE})

    def test_no_executor_is_registered_for_mutations(self):
        # Vocabulary and policy only. Writes and deletes are evaluable but not
        # executable, so a proposal fails closed at dispatch rather than touching disk.
        from agentgate.executors import build_default_executor_registry

        registry = build_default_executor_registry()
        try:
            for verb in ("FILE_WRITE", "FILE_DELETE"):
                self.assertIsNone(registry.resolve(verb, {}), verb)
        finally:
            registry.close()


if __name__ == "__main__":
    unittest.main()
