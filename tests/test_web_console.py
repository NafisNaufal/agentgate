"""Demo Console tests, concentrated on the properties that matter when it is exposed.

The console is network-reachable and can read and send a connected Gmail account, so
these assert the gates hold: no password, no access; no CSRF token, no state change;
and Gmail OAuth refuses an origin Google would reject rather than failing cryptically
at the redirect.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from agentgate.web.auth import (
    AuthNotConfigured,
    SessionStore,
    check_password,
    load_password,
)
from agentgate.web.jobs import JobManager
from agentgate.web.oauth import oauth_blocked_reason, origin_is_oauth_capable, redirect_uri_for


class TestPasswordGate(unittest.TestCase):
    def test_console_refuses_to_start_without_a_password(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(AuthNotConfigured):
                load_password()

    def test_short_password_is_refused(self):
        with patch.dict("os.environ", {"AGENTGATE_WEB_PASSWORD": "short"}, clear=True):
            with self.assertRaises(AuthNotConfigured):
                load_password()

    def test_password_comparison_rejects_near_misses(self):
        self.assertTrue(check_password("correct-horse", "correct-horse"))
        self.assertFalse(check_password("correct-hors", "correct-horse"))
        self.assertFalse(check_password("", "correct-horse"))


class TestSessions(unittest.TestCase):
    def test_session_issues_a_distinct_csrf_token(self):
        store = SessionStore()
        token, csrf = store.create()
        self.assertNotEqual(token, csrf)
        self.assertEqual(store.csrf_for(token), csrf)
        self.assertTrue(store.is_valid(token))

    def test_unknown_and_missing_tokens_are_invalid(self):
        store = SessionStore()
        self.assertFalse(store.is_valid("nope"))
        self.assertFalse(store.is_valid(None))
        self.assertIsNone(store.csrf_for("nope"))

    def test_expired_session_stops_working(self):
        store = SessionStore(ttl=-1)
        token, _ = store.create()
        self.assertFalse(store.is_valid(token))

    def test_logout_invalidates_the_session(self):
        store = SessionStore()
        token, _ = store.create()
        store.destroy(token)
        self.assertFalse(store.is_valid(token))

    def test_sessions_are_independent(self):
        store = SessionStore()
        a, csrf_a = store.create()
        b, csrf_b = store.create()
        self.assertNotEqual(csrf_a, csrf_b)
        store.destroy(a)
        self.assertTrue(store.is_valid(b))


class TestOAuthOriginRules(unittest.TestCase):
    """Google only accepts plain http redirects to loopback; everything else needs TLS."""

    def test_loopback_http_is_allowed(self):
        for origin in ("http://localhost:8080", "http://127.0.0.1:8080"):
            self.assertTrue(origin_is_oauth_capable(origin), origin)

    def test_https_is_allowed_anywhere(self):
        self.assertTrue(origin_is_oauth_capable("https://agentgate.example.com"))

    def test_public_http_is_refused(self):
        for origin in ("http://103.179.134.116:8080", "http://agentgate.example.com"):
            self.assertFalse(origin_is_oauth_capable(origin), origin)

    def test_blocked_reason_names_the_origin_and_the_fix(self):
        reason = oauth_blocked_reason("http://203.0.113.5:8080")
        self.assertIn("203.0.113.5", reason)
        self.assertIn("localhost", reason)

    def test_redirect_uri_is_built_off_the_origin(self):
        self.assertEqual(
            redirect_uri_for("http://localhost:8080/"), "http://localhost:8080/oauth/callback"
        )


class TestJobManager(unittest.TestCase):
    def test_job_failure_is_captured_without_a_traceback(self):
        manager = JobManager()

        def work(_emit):
            raise RuntimeError("planner exploded")

        job = manager.submit("boom", "scenario", work)
        _wait(manager, job.id)
        finished = manager.get(job.id)
        self.assertEqual(finished.status, "error")
        self.assertIn("RuntimeError", finished.error)
        self.assertNotIn("Traceback", finished.error)

    def test_history_is_bounded(self):
        manager = JobManager(max_history=3)
        for n in range(6):
            job = manager.submit(f"job{n}", "scenario", _immediate)
            _wait(manager, job.id)
        self.assertLessEqual(len(manager.recent()), 3)


class TestActiveJobSurvivesReload(unittest.TestCase):
    """A browser reload must not orphan a run that is still going server-side.

    The console previously held the job id only in a page variable, so refreshing
    during a multi-minute run left it running with nobody watching.
    """

    def test_active_reports_the_running_job(self):
        import threading

        manager = JobManager()
        release = threading.Event()

        def slow(_emit):
            release.wait(timeout=5)
            return "done", "finished"

        job = manager.submit("slow", "scenario", slow)
        for _ in range(500):
            if manager.active() is not None:
                break
            import time as _t

            _t.sleep(0.01)
        active = manager.active()
        self.assertIsNotNone(active)
        self.assertEqual(active.id, job.id)
        release.set()
        _wait(manager, job.id)
        self.assertIsNone(manager.active())

    def test_no_active_job_when_idle(self):
        self.assertIsNone(JobManager().active())


class TestEvalJobShape(unittest.TestCase):
    def test_rows_stream_as_they_complete(self):
        manager = JobManager()

        def work(emit):
            for n in range(3):
                emit({"id": f"CASE-{n}", "match": n != 1})
            return "eval_complete", "2/3 cases match the expected decision"

        job = manager.submit("eval", "eval", work)
        job.total = 3
        _wait(manager, job.id)
        finished = manager.get(job.id).to_dict()
        self.assertEqual(finished["kind"], "eval")
        self.assertEqual(finished["total"], 3)
        self.assertEqual(len(finished["steps"]), 3)
        self.assertEqual(sum(1 for r in finished["steps"] if r["match"]), 2)
        self.assertIn("2/3", finished["final_message"])


def _immediate(_emit):
    return "done", "finished"


def _wait(manager: JobManager, job_id: str, timeout: float = 5.0) -> None:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        job = manager.get(job_id)
        if job and job.status in {"done", "error"}:
            return
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} did not finish")


if __name__ == "__main__":
    unittest.main()
