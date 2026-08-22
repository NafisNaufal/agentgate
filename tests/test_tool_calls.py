"""Tool-call and action-vocabulary tests.

Covers:
  1. _REQUIRED_ARGS coverage — every verb, every required key enforced.
  2. Tool metadata immutability — registry overwrite, planner cannot weaken.
  3. content_fields actually reaches detectors — raw_payload carries content.
"""

from __future__ import annotations

import unittest

from agentgate.action_space import ActionSpaceError, _REQUIRED_ARGS, validate_proposal
from agentgate.planner.base import Proposal
from agentgate.tool_specs.base import ToolSpec
from agentgate.tools import ToolRegistry
from agentgate.schemas import ACTION_TYPES


class TestRequiredArgsCoverage(unittest.TestCase):
    """Every action verb and every declared required arg must be enforced."""

    def test_required_args_keys_match_vocabulary(self):
        self.assertEqual(set(_REQUIRED_ARGS), set(ACTION_TYPES))

    def test_every_declared_required_arg_is_enforced(self):
        for action_type, required in sorted(_REQUIRED_ARGS.items()):
            for key in required:
                with self.subTest(action_type=action_type, missing=key):
                    args = {k: f"value-{k}" for k in required if k != key}
                    with self.assertRaises(ActionSpaceError) as cm:
                        validate_proposal(action_type, args)
                    self.assertIn(key, str(cm.exception))

    def test_valid_args_accept_for_every_verb(self):
        for action_type, required in sorted(_REQUIRED_ARGS.items()):
            with self.subTest(action_type=action_type):
                validate_proposal(action_type, {k: f"v-{k}" for k in required})

    def test_empty_required_verbs_accept_no_args(self):
        for action_type, required in sorted(_REQUIRED_ARGS.items()):
            if not required:
                with self.subTest(action_type=action_type):
                    validate_proposal(action_type, {})

    def test_missing_arguments_object_rejected_when_required(self):
        for action_type, required in sorted(_REQUIRED_ARGS.items()):
            if required:
                with self.subTest(action_type=action_type):
                    with self.assertRaises(ActionSpaceError):
                        validate_proposal(action_type, None)


class TestToolMetadataImmutability(unittest.TestCase):
    """A planner must not be able to weaken a registered tool's metadata."""

    def test_weaker_replacement_is_rejected_by_registry(self):
        reg = ToolRegistry()
        original = reg.get("gmail_send")
        self.assertIsNotNone(original)
        weaker = ToolSpec(
            name=original.name,
            target_system=original.target_system,
            action_type=original.action_type,
            channel=original.channel,
            rollback_available=True,
            default_risk_hints=(),
            content_fields=(),
            description=original.description,
        )
        reg.register(weaker)
        # The registry should still return the original spec; if it doesn't,
        # this documents the gap where register() silently overwrites.
        self.assertIs(reg.get("gmail_send"), original)

    def test_planner_cannot_weaken_rollback_via_proposal(self):
        reg = ToolRegistry()
        # gmail_send spec has rollback_available=False.
        # Planner claims rollback_available=True — must not flip it to True.
        proposal = Proposal(
            action_type="API_CALL",
            arguments={"tool_name": "gmail_send", "to": "a@b.c"},
            rollback_available=True,
        )
        req = proposal.to_action_request(tool_registry=reg)
        self.assertFalse(req.rollback_available)

    def test_planner_cannot_strip_default_risk_hints(self):
        reg = ToolRegistry()
        proposal = Proposal(
            action_type="API_CALL",
            arguments={"tool_name": "gmail_send", "to": "a@b.c"},
            risk_hint=[],
        )
        req = proposal.to_action_request(tool_registry=reg)
        self.assertIn("external_send", req.risk_hint)


class TestContentFieldsReachDetectors(unittest.TestCase):
    """content_fields on a ToolSpec must control what lands in raw_payload."""

    def test_gmail_body_reaches_raw_payload(self):
        body = "UNIQUE-CANARY-BODY-7f3a"
        proposal = Proposal(
            action_type="API_CALL",
            arguments={
                "tool_name": "gmail_send",
                "to": "x@y.z",
                "subject": "s",
                "body": body,
            },
            rationale="test",
        )
        req = proposal.to_action_request(tool_registry=ToolRegistry())
        self.assertIn(body, req.raw_payload)

    def test_empty_content_fields_excludes_body(self):
        reg = ToolRegistry()
        reg.register(
            ToolSpec(
                "opaque_send",
                "Opaque",
                content_fields=(),
            )
        )
        body = "UNIQUE-CANARY-BODY-7f3a"
        proposal = Proposal(
            action_type="API_CALL",
            arguments={
                "tool_name": "opaque_send",
                "body": body,
            },
        )
        req = proposal.to_action_request(tool_registry=reg)
        self.assertNotIn(body, req.raw_payload)


if __name__ == "__main__":
    unittest.main()
