"""Audit store tests (PRD F14).

The real store talks to Postgres, so these drive it through a fake psycopg module:
enough to assert the schema is created, what actually gets written, that credentials
never leak into errors, and that an unavailable audit store fails loudly rather than
letting an unaudited decision through.
"""

from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch

from agentgate import audit
from agentgate.audit import AuditUnavailable, PostgresAuditStore, build_audit_store
from agentgate.decision import DecisionEngine
from agentgate.schemas import ActionRequest, Decision, DecisionResponse, RiskLevel


class FakeCursor:
    def __init__(self, connection: "FakeConnection") -> None:
        self._conn = connection

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        if self._conn.fail_on and self._conn.fail_on in sql:
            raise RuntimeError("boom")
        self._conn.statements.append((sql, params))

    def fetchall(self) -> list[tuple]:
        return self._conn.rows


class FakeConnection:
    def __init__(self, rows: list[tuple] | None = None, fail_on: str = "") -> None:
        self.statements: list[tuple[str, tuple]] = []
        self.rows = rows if rows is not None else [(0, 0)]
        self.fail_on = fail_on
        self.closed = False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def close(self) -> None:
        self.closed = True


def fake_psycopg(connection: FakeConnection | None = None, connect_error: Exception | None = None):
    """Install a stand-in psycopg module and return the connection it hands out."""
    conn = connection or FakeConnection()

    def connect(dsn: str, **_: object) -> FakeConnection:
        if connect_error:
            raise connect_error
        return conn

    module = types.ModuleType("psycopg")
    module.connect = connect
    json_module = types.ModuleType("psycopg.types.json")
    json_module.Jsonb = lambda value: value
    types_module = types.ModuleType("psycopg.types")
    types_module.json = json_module
    return conn, {
        "psycopg": module,
        "psycopg.types": types_module,
        "psycopg.types.json": json_module,
    }


def decision_response(decision: Decision = Decision.ALLOW) -> DecisionResponse:
    return DecisionResponse(
        decision=decision,
        risk_level=RiskLevel.LOW,
        risk_score=0.1,
        reasons=["clean"],
    )


class TestBuildAuditStore(unittest.TestCase):
    def test_missing_dsn_fails_loudly(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(AuditUnavailable) as ctx:
                build_audit_store()
        self.assertIn("AGENTGATE_AUDIT_DSN", str(ctx.exception))

    def test_blank_dsn_is_treated_as_missing(self):
        with patch.dict("os.environ", {"AGENTGATE_AUDIT_DSN": "   "}, clear=True):
            with self.assertRaises(AuditUnavailable):
                build_audit_store()

    def test_unreachable_database_reports_without_credentials(self):
        _, modules = fake_psycopg(connect_error=OSError("connection refused"))
        with patch.dict(sys.modules, modules):
            with self.assertRaises(AuditUnavailable) as ctx:
                PostgresAuditStore("postgresql://agentgate:hunter2@db.internal:5432/agentgate")
        message = str(ctx.exception)
        self.assertNotIn("hunter2", message)
        self.assertIn("***", message)

    def test_safe_dsn_leaves_credential_free_urls_alone(self):
        self.assertEqual(
            audit._safe_dsn("postgresql://localhost:5432/agentgate"),
            "postgresql://localhost:5432/agentgate",
        )


class TestPostgresAuditStore(unittest.TestCase):
    def _store(self, **kwargs) -> tuple[PostgresAuditStore, FakeConnection]:
        conn, modules = fake_psycopg(**kwargs)
        with patch.dict(sys.modules, modules):
            store = PostgresAuditStore("postgresql://localhost:5432/agentgate")
        return store, conn

    def test_schema_is_created_on_connect(self):
        _, conn = self._store()
        self.assertIn("CREATE TABLE IF NOT EXISTS agentgate_audit", conn.statements[0][0])

    def test_record_stamps_audit_id_onto_the_response(self):
        store, conn = self._store()
        response = decision_response()
        self.assertEqual(response.audit_id, "")
        audit_id = store.record(ActionRequest(action_type="FILE_READ"), response)
        self.assertTrue(audit_id.startswith("aud_"))
        self.assertEqual(response.audit_id, audit_id)
        self.assertIn("INSERT INTO agentgate_audit", conn.statements[-1][0])

    def test_recorded_request_is_sanitized(self):
        store, conn = self._store()
        token = "ghp_" + "a" * 36
        store.record(
            ActionRequest(action_type="API_CALL", raw_payload=f"push {token}"),
            decision_response(),
        )
        written = repr(conn.statements[-1][1])
        self.assertNotIn(token, written)
        self.assertIn("REDACTED_GITHUB_TOKEN", written)

    def test_need_approval_is_recorded_as_awaiting_approval(self):
        store, conn = self._store()
        store.record(
            ActionRequest(action_type="BROWSER_SUBMIT"),
            decision_response(Decision.NEED_APPROVAL),
        )
        self.assertIn("awaiting_approval", conn.statements[-1][1])

    def test_default_stage_is_a_proposed_action(self):
        store, conn = self._store()
        store.record(ActionRequest(action_type="FILE_READ"), decision_response())
        self.assertIn(audit.STAGE_ACTION, conn.statements[-1][1])

    def test_internal_screens_are_recorded_under_their_own_stage(self):
        store, conn = self._store()
        store.record(
            ActionRequest(action_type="FILE_READ"),
            decision_response(),
            audit.STAGE_OBSERVATION_SCREEN,
        )
        self.assertIn(audit.STAGE_OBSERVATION_SCREEN, conn.statements[-1][1])
        self.assertNotIn(audit.STAGE_ACTION, conn.statements[-1][1])

    def test_completeness_counts_actions_only(self):
        store, conn = self._store(connection=FakeConnection(rows=[(3, 3)]))
        store.completeness()
        sql, params = conn.statements[-1]
        self.assertIn("WHERE stage = %s", sql)
        self.assertEqual(params, (audit.STAGE_ACTION,))

    def test_update_writes_only_the_supplied_columns(self):
        store, conn = self._store()
        store.update("aud_1", execution_status="executed")
        sql, params = conn.statements[-1]
        self.assertIn("execution_status = %s", sql)
        self.assertNotIn("reviewer_status", sql)
        self.assertEqual(params, ("executed", "aud_1"))

    def test_update_with_nothing_to_set_is_a_no_op(self):
        store, conn = self._store()
        before = len(conn.statements)
        store.update("aud_1")
        self.assertEqual(len(conn.statements), before)

    def test_completeness_of_an_empty_log_is_one(self):
        store, _ = self._store(connection=FakeConnection(rows=[(0, 0)]))
        self.assertEqual(store.completeness(), 1.0)

    def test_completeness_reports_the_recorded_fraction(self):
        store, _ = self._store(connection=FakeConnection(rows=[(200, 199)]))
        self.assertEqual(store.completeness(), 0.995)

    def test_write_failure_is_reported_as_audit_unavailable(self):
        store, _ = self._store(connection=FakeConnection(fail_on="INSERT"))
        with self.assertRaises(AuditUnavailable):
            store.record(ActionRequest(action_type="FILE_READ"), decision_response())

    def test_close_releases_the_connection(self):
        store, conn = self._store()
        store.close()
        self.assertTrue(conn.closed)


class TestEngineRequiresAudit(unittest.TestCase):
    def test_engine_refuses_to_build_without_an_audit_store(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(AuditUnavailable):
                DecisionEngine(detectors=[])

    def test_evaluate_records_every_decision(self):
        from tests.fake_audit import FakeAuditStore

        store = FakeAuditStore()
        engine = DecisionEngine(detectors=[], audit_store=store)
        response = engine.evaluate(ActionRequest(action_type="FILE_READ"))
        self.assertEqual(len(store.records), 1)
        self.assertIn(response.audit_id, store.records)
        self.assertEqual(store.completeness(), 1.0)


if __name__ == "__main__":
    unittest.main()
