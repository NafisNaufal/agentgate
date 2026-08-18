"""Audit log (PRD F14), backed by Postgres.

Every evaluated action is recorded with its request, decision, reasons, sensitive
entities, reviewer status, execution status, and timestamp. Auditing is mandatory:
there is no in-memory fallback and no silent degradation, because the PRD measures
audit completeness (>= 95% of action logs carrying request, decision, reasons, status
and timestamp) as a success metric. A run that cannot be audited fails loudly instead
of quietly producing unaudited decisions.

Configuration::

    AGENTGATE_AUDIT_DSN=postgresql://user:pass@host:5432/agentgate

The stored request and response are passed through the sanitizer first. The audit
trail records *what was decided and why*, not the live secret that triggered it -
otherwise the audit database becomes the largest single collection of the very
credentials the guardrail exists to contain.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .executors.base import safe_value
from .schemas import ActionRequest, DecisionResponse

AUDIT_DSN_ENV = "AGENTGATE_AUDIT_DSN"
TABLE = "agentgate_audit"

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    audit_id            TEXT PRIMARY KEY,
    created_at          TIMESTAMPTZ  NOT NULL,
    stage               TEXT         NOT NULL,
    action_type         TEXT         NOT NULL,
    domain              TEXT         NOT NULL,
    target_system       TEXT         NOT NULL,
    tool_name           TEXT         NOT NULL,
    decision            TEXT         NOT NULL,
    risk_level          TEXT         NOT NULL,
    risk_score          DOUBLE PRECISION NOT NULL,
    reasons             JSONB        NOT NULL,
    triggered_policies  JSONB        NOT NULL,
    sensitive_entities  JSONB        NOT NULL,
    request             JSONB        NOT NULL,
    response            JSONB        NOT NULL,
    execution_status    TEXT         NOT NULL,
    reviewer_status     TEXT         NOT NULL,
    execution_result    JSONB
);
CREATE INDEX IF NOT EXISTS {TABLE}_created_at_idx ON {TABLE} (created_at DESC);
CREATE INDEX IF NOT EXISTS {TABLE}_decision_idx   ON {TABLE} (decision);
CREATE INDEX IF NOT EXISTS {TABLE}_stage_idx      ON {TABLE} (stage);
"""


class AuditUnavailable(RuntimeError):
    """Raised when the audit store is not configured or not reachable."""


# What produced this evaluation. Only ACTION rows are proposed tool calls; the others
# are internal guardrail screens the loop performs on text flowing in or out. Keeping
# them apart matters because the PRD's action-evaluation and audit-completeness metrics
# count proposed actions, and mixing screens in would inflate both.
STAGE_ACTION = "action"
STAGE_TASK_SCREEN = "task_screen"
STAGE_TERMINAL_SCREEN = "terminal_screen"
STAGE_OBSERVATION_SCREEN = "observation_screen"


@dataclass
class AuditRecord:
    """One audited evaluation, in the shape PRD F14 requires."""

    audit_id: str
    timestamp: float
    stage: str
    request: dict[str, Any]
    response: dict[str, Any]
    execution_status: str = "pending"
    reviewer_status: str = "none"
    execution_result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "stage": self.stage,
            "iso_time": time.strftime(
                "%Y-%m-%dT%H:%M:%S%z", time.localtime(self.timestamp)
            ),
            "request": self.request,
            "response": self.response,
            "execution_status": self.execution_status,
            "reviewer_status": self.reviewer_status,
            "execution_result": self.execution_result,
        }


class PostgresAuditStore:
    """Persistent audit trail. Connects eagerly so misconfiguration surfaces at startup."""

    def __init__(self, dsn: str, *, connect_timeout: int = 10):
        try:
            import psycopg
            from psycopg.types.json import Jsonb
        except ImportError as exc:  # pragma: no cover - depends on install state
            raise AuditUnavailable(
                "psycopg is required for the audit store. Install it with "
                "'python3 -m pip install -e .'"
            ) from exc

        self._json = Jsonb
        try:
            self._conn = psycopg.connect(dsn, connect_timeout=connect_timeout, autocommit=True)
            with self._conn.cursor() as cur:
                cur.execute(SCHEMA)
        except Exception as exc:
            raise AuditUnavailable(
                f"Cannot reach the audit database at {_safe_dsn(dsn)}: {exc}"
            ) from exc

    def record(
        self,
        req: ActionRequest,
        decision: DecisionResponse,
        stage: str = STAGE_ACTION,
    ) -> str:
        """Persist one evaluation and stamp its audit_id onto the response."""
        audit_id = "aud_" + uuid.uuid4().hex[:12]
        decision.audit_id = audit_id
        request = safe_value(req.to_dict())
        response = safe_value(decision.to_dict())
        execution_status = (
            "awaiting_approval" if decision.decision.value == "NEED_APPROVAL" else "pending"
        )
        self._execute(
            f"""
            INSERT INTO {TABLE} (
                audit_id, created_at, stage, action_type, domain, target_system, tool_name,
                decision, risk_level, risk_score, reasons, triggered_policies,
                sensitive_entities, request, response, execution_status, reviewer_status
            ) VALUES (%s, now(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                audit_id,
                stage,
                req.action_type,
                req.domain,
                req.target_system,
                req.tool_name,
                decision.decision.value,
                decision.risk_level.value,
                decision.risk_score,
                self._json(response["reasons"]),
                self._json(response["triggered_policies"]),
                self._json(response["sensitive_entities"]),
                self._json(request),
                self._json(response),
                execution_status,
                "none",
            ),
        )
        return audit_id

    def update(
        self,
        audit_id: str,
        *,
        execution_status: str | None = None,
        reviewer_status: str | None = None,
        execution_result: dict[str, Any] | None = None,
    ) -> None:
        """Record what happened after the decision (enforcement, reviewer verdict)."""
        assignments: list[str] = []
        values: list[Any] = []
        if execution_status is not None:
            assignments.append("execution_status = %s")
            values.append(execution_status)
        if reviewer_status is not None:
            assignments.append("reviewer_status = %s")
            values.append(reviewer_status)
        if execution_result is not None:
            assignments.append("execution_result = %s")
            values.append(self._json(safe_value(execution_result)))
        if not assignments:
            return
        values.append(audit_id)
        self._execute(
            f"UPDATE {TABLE} SET {', '.join(assignments)} WHERE audit_id = %s", tuple(values)
        )

    def get(self, audit_id: str) -> AuditRecord | None:
        rows = self._query(
            f"""
            SELECT audit_id, extract(epoch from created_at), stage, request, response,
                   execution_status, reviewer_status, execution_result
            FROM {TABLE} WHERE audit_id = %s
            """,
            (audit_id,),
        )
        if not rows:
            return None
        audit, created, stage, request, response, execution_status, reviewer, result = rows[0]
        return AuditRecord(
            audit_id=audit,
            timestamp=float(created),
            stage=stage,
            request=request,
            response=response,
            execution_status=execution_status,
            reviewer_status=reviewer,
            execution_result=result,
        )

    def completeness(self) -> float:
        """Fraction of audited actions carrying request, decision, status, timestamp (F14).

        Counts proposed actions only; internal screens are not actions the PRD metric
        is measured over.
        """
        rows = self._query(
            f"""
            SELECT count(*), count(*) FILTER (
                WHERE request IS NOT NULL AND response IS NOT NULL
                  AND execution_status <> '' AND created_at IS NOT NULL
            )
            FROM {TABLE} WHERE stage = %s
            """,
            (STAGE_ACTION,),
        )
        total, complete = rows[0]
        if not total:
            return 1.0
        return round(complete / total, 4)

    def close(self) -> None:
        self._conn.close()

    # --- transport -------------------------------------------------------

    def _execute(self, sql: str, params: tuple[Any, ...]) -> None:
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, params)
        except Exception as exc:
            raise AuditUnavailable(f"Audit write failed: {exc}") from exc

    def _query(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()
        except Exception as exc:
            raise AuditUnavailable(f"Audit read failed: {exc}") from exc


def build_audit_store(dsn: str | None = None) -> PostgresAuditStore:
    """Build the audit store from ``AGENTGATE_AUDIT_DSN``, failing loudly if unset."""
    resolved = dsn or os.environ.get(AUDIT_DSN_ENV, "")
    if not resolved.strip():
        raise AuditUnavailable(
            f"{AUDIT_DSN_ENV} is not set. AgentGate requires a Postgres audit store; "
            "export it as postgresql://user:pass@host:5432/agentgate"
        )
    return PostgresAuditStore(resolved.strip())


def _safe_dsn(dsn: str) -> str:
    """Strip credentials so a connection error never prints the password."""
    if "@" not in dsn:
        return dsn
    scheme, _, rest = dsn.partition("://")
    return f"{scheme}://***@{rest.rpartition('@')[2]}" if rest else dsn
