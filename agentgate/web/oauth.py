"""Browser-redirect Gmail OAuth for the Demo Console.

Different flow from the CLI's loopback server: here the console *is* the web app, so
Google redirects straight back to ``/oauth/callback``.

The constraint that shapes this module: Google only accepts a plain-``http`` redirect
URI when the host is ``localhost`` or ``127.0.0.1``. Everything else must be HTTPS. So
a console reached at ``http://<public-ip>:8080`` cannot complete the flow, and saying
so up front is far kinder than letting Google return redirect_uri_mismatch. Reach the
console over an SSH tunnel to connect Gmail, or put it behind HTTPS.
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..executors.google_auth import (
    AUTH_ENDPOINT,
    TOKEN_ENDPOINT,
    AuthError,
    GoogleOAuthConfig,
    load_config,
)

CALLBACK_PATH = "/oauth/callback"
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
_STATE_TTL_SECONDS = 600


def redirect_uri_for(origin: str) -> str:
    return origin.rstrip("/") + CALLBACK_PATH


def origin_is_oauth_capable(origin: str) -> bool:
    """Whether Google will accept a redirect back to this origin."""
    parts = urlsplit(origin)
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and (parts.hostname or "") in _LOOPBACK_HOSTS


def oauth_blocked_reason(origin: str) -> str:
    return (
        f"Google only allows http:// OAuth redirects to localhost, and this console is "
        f"being reached at {origin}. Open it over an SSH tunnel "
        f"(ssh -L 8080:127.0.0.1:8080 …) and connect Gmail from http://localhost:8080, "
        f"or serve the console over HTTPS."
    )


class GmailConnection:
    """Tracks pending OAuth states and reports whether Gmail is connected."""

    def __init__(self) -> None:
        self._pending: dict[str, float] = {}

    # --- status ----------------------------------------------------------

    def status(self) -> dict[str, Any]:
        try:
            cfg = load_config()
        except AuthError as exc:
            return {"configured": False, "connected": False, "detail": str(exc)}
        token = self._read_token(cfg.token_file)
        if token is None:
            return {
                "configured": True,
                "connected": False,
                "detail": "Google credentials are configured; account not connected yet.",
            }
        expires_at = float(token.get("expires_at", 0))
        return {
            "configured": True,
            "connected": True,
            "scopes": list(cfg.scopes),
            "token_file": str(cfg.token_file),
            "access_token_valid_for": max(0, int(expires_at - time.time())),
            "can_refresh": bool(token.get("refresh_token")),
            "detail": "Connected.",
        }

    # --- flow ------------------------------------------------------------

    def start(self, origin: str) -> str:
        cfg = load_config()
        if not origin_is_oauth_capable(origin):
            raise AuthError(oauth_blocked_reason(origin))
        state = secrets.token_urlsafe(24)
        self._pending[state] = time.time() + _STATE_TTL_SECONDS
        self._prune()
        query = urllib.parse.urlencode(
            {
                "client_id": cfg.client_id,
                "redirect_uri": redirect_uri_for(origin),
                "response_type": "code",
                "scope": " ".join(cfg.scopes),
                "state": state,
                "access_type": "offline",
                "prompt": "consent",
            }
        )
        return f"{AUTH_ENDPOINT}?{query}"

    def finish(self, origin: str, code: str, state: str) -> None:
        expires = self._pending.pop(state, None)
        if expires is None or expires < time.time():
            raise AuthError("OAuth state is unknown or expired; start the connection again")
        cfg = load_config()
        token = self._exchange(
            {
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri_for(origin),
            }
        )
        if not token.get("refresh_token"):
            raise AuthError("Google returned no refresh token; try connecting again")
        self._write_token(
            cfg.token_file,
            {
                "access_token": token["access_token"],
                "refresh_token": token["refresh_token"],
                "expires_at": time.time() + float(token.get("expires_in", 3600)),
            },
        )

    def disconnect(self) -> None:
        cfg = load_config()
        Path(cfg.token_file).unlink(missing_ok=True)

    # --- internals -------------------------------------------------------

    @staticmethod
    def _exchange(fields: dict[str, str]) -> dict[str, Any]:
        request = urllib.request.Request(
            TOKEN_ENDPOINT,
            data=urllib.parse.urlencode(fields).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read(1_048_576).decode("utf-8"))
        except Exception as exc:
            # `fields` carries the client secret; never interpolate it.
            raise AuthError(f"Google token exchange failed ({type(exc).__name__})") from None
        if not isinstance(payload, dict) or "access_token" not in payload:
            raise AuthError("Google token endpoint returned an unexpected response")
        return payload

    @staticmethod
    def _read_token(path: Path) -> dict[str, Any] | None:
        try:
            if not Path(path).exists():
                return None
            data = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) and "access_token" in data else None

    @staticmethod
    def _write_token(path: Path, token: dict[str, Any]) -> None:
        import stat

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(token, indent=2))
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def _prune(self) -> None:
        now = time.time()
        for state in [s for s, exp in self._pending.items() if exp < now]:
            self._pending.pop(state, None)


__all__ = [
    "CALLBACK_PATH",
    "GmailConnection",
    "GoogleOAuthConfig",
    "oauth_blocked_reason",
    "origin_is_oauth_capable",
    "redirect_uri_for",
]
