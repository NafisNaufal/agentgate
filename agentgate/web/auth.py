"""Shared-password auth for the Demo Console.

The console is reachable over the network and can read and send a connected Gmail
account, so it is never open. A single shared password gates everything except the
login endpoint itself.

Deliberately modest: in-memory sessions, one shared secret, no user accounts. That is
the right size for an MVP demo console, and it is stated plainly rather than dressed
up as more than it is.
"""

from __future__ import annotations

import hmac
import os
import secrets
import time

PASSWORD_ENV = "AGENTGATE_WEB_PASSWORD"
SESSION_COOKIE = "agentgate_session"
CSRF_HEADER = "X-AgentGate-CSRF"
SESSION_TTL_SECONDS = 12 * 3600
# Enough to make online guessing pointless without needing a lockout table.
_LOGIN_DELAY_SECONDS = 0.5


class AuthNotConfigured(RuntimeError):
    """Raised when the console is started without a password."""


def load_password() -> str:
    password = os.environ.get(PASSWORD_ENV, "")
    if len(password.strip()) < 8:
        raise AuthNotConfigured(
            f"{PASSWORD_ENV} must be set to at least 8 characters. The console exposes "
            "Gmail access and scenario execution; it does not run unauthenticated."
        )
    return password


class SessionStore:
    """In-memory sessions. Restarting the console logs everyone out, which is fine."""

    def __init__(self, ttl: int = SESSION_TTL_SECONDS) -> None:
        self._sessions: dict[str, tuple[float, str]] = {}
        self._ttl = ttl

    def create(self) -> tuple[str, str]:
        """Return (session_token, csrf_token)."""
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        self._sessions[token] = (time.time() + self._ttl, csrf)
        self._prune()
        return token, csrf

    def csrf_for(self, token: str | None) -> str | None:
        if not token:
            return None
        entry = self._sessions.get(token)
        if entry is None:
            return None
        expires, csrf = entry
        if expires < time.time():
            self._sessions.pop(token, None)
            return None
        return csrf

    def is_valid(self, token: str | None) -> bool:
        return self.csrf_for(token) is not None

    def destroy(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)

    def _prune(self) -> None:
        now = time.time()
        for token in [t for t, (exp, _) in self._sessions.items() if exp < now]:
            self._sessions.pop(token, None)


def check_password(supplied: str, expected: str) -> bool:
    """Constant-time comparison, with a small delay to blunt online guessing."""
    time.sleep(_LOGIN_DELAY_SECONDS)
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))
