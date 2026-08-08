from __future__ import annotations

import base64
import io
import json
import unittest
import urllib.error
from typing import Any

from agentgate.executors.github import GitHubExecutor


class FakeResponse:
    def __init__(self, data: Any) -> None:
        self.body = json.dumps(data).encode("utf-8")

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        return None


class QueueOpener:
    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: float) -> FakeResponse:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return FakeResponse(response)


class TestGitHubExecutor(unittest.TestCase):
    token = "unit-test-token-value"

    def execute(self, response: Any, tool_name: str, **arguments: Any):
        opener = QueueOpener(response)
        executor = GitHubExecutor(token=self.token, opener=opener)
        result = executor.execute(
            "API_CALL", {"tool_name": tool_name, **arguments}
        )
        return result, opener.requests[0]

    def test_read_repo_returns_safe_metadata(self):
        result, request = self.execute(
            {
                "id": 7,
                "name": "demo",
                "full_name": "octo/demo",
                "private": False,
                "default_branch": "main",
                "owner": {"login": "octo", "id": 2, "type": "User", "email": "hidden@example.com"},
                "hooks_url": "not-returned",
            },
            "github_read_repo",
            owner="octo",
            repo="demo",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data["owner"]["login"], "octo")
        self.assertNotIn("hooks_url", result.data)
        self.assertEqual(request.get_method(), "GET")

    def test_read_file_decodes_base64(self):
        encoded = base64.b64encode(b"hello from repository").decode("ascii")
        result, request = self.execute(
            {"type": "file", "name": "readme.txt", "path": "docs/readme.txt", "content": encoded, "encoding": "base64"},
            "github_read_file",
            owner="octo",
            repo="demo",
            path="docs/readme.txt",
            ref="test-branch",
        )
        self.assertEqual(result.data["content"], "hello from repository")
        self.assertIn("ref=test-branch", request.full_url)

    def test_create_issue(self):
        result, request = self.execute(
            {"id": 1, "number": 9, "title": "Test issue", "state": "open", "html_url": "https://example.test/9"},
            "github_create_issue",
            owner="octo",
            repo="demo",
            title="Test issue",
            body="Test body",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data["number"], 9)
        self.assertEqual(json.loads(request.data), {"title": "Test issue", "body": "Test body"})

    def test_create_issue_comment(self):
        result, request = self.execute(
            {"id": 4, "html_url": "https://example.test/comment/4", "created_at": "now"},
            "github_create_issue_comment",
            owner="octo",
            repo="demo",
            issue_number=3,
            body="Looks good",
        )
        self.assertTrue(result.success)
        self.assertIn("/issues/3/comments", request.full_url)
        self.assertEqual(json.loads(request.data)["body"], "Looks good")

    def test_issue_number_must_be_an_integer(self):
        result = GitHubExecutor(token=self.token, opener=QueueOpener({})).execute(
            "API_CALL",
            {
                "tool_name": "github_create_issue_comment",
                "owner": "octo",
                "repo": "demo",
                "issue_number": 1.9,
                "body": "No conversion",
            },
        )
        self.assertFalse(result.success)
        self.assertEqual(result.status, "invalid_arguments")

    def test_create_gist(self):
        result, request = self.execute(
            {"id": "abc", "html_url": "https://gist.example/abc", "public": False},
            "github_create_gist",
            description="Dummy test gist",
            public=False,
            files={"demo.py": {"content": "print('demo')"}},
        )
        self.assertTrue(result.success)
        body = json.loads(request.data)
        self.assertEqual(body["files"]["demo.py"]["content"], "print('demo')")
        self.assertFalse(body["public"])

    def test_create_gist_rejects_string_visibility(self):
        opener = QueueOpener({"id": "must-not-be-used"})
        result = GitHubExecutor(token=self.token, opener=opener).execute(
            "API_CALL",
            {
                "tool_name": "github_create_gist",
                "public": "false",
                "files": {"demo.txt": "demo"},
            },
        )
        self.assertEqual(result.status, "invalid_arguments")
        self.assertEqual(opener.requests, [])

    def test_insecure_non_loopback_api_url_is_rejected_before_transport(self):
        opener = QueueOpener({"id": 1})
        result = GitHubExecutor(
            token=self.token,
            api_url="http://github.example.test/api/v3",
            opener=opener,
        ).execute(
            "API_CALL",
            {"tool_name": "github_read_repo", "owner": "octo", "repo": "demo"},
        )
        self.assertEqual(result.status, "configuration_error")
        self.assertEqual(opener.requests, [])

    def test_api_failure_is_controlled_and_token_is_redacted(self):
        error = urllib.error.HTTPError(
            "https://api.github.com/repos/octo/demo",
            401,
            "Unauthorized",
            {},
            io.BytesIO(json.dumps({"message": f"bad token {self.token}"}).encode("utf-8")),
        )
        result, _ = self.execute(error, "github_read_repo", owner="octo", repo="demo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "api_error")
        self.assertNotIn(self.token, result.error)
        self.assertNotIn(self.token, json.dumps(result.to_dict()))

    def test_unexpected_transport_error_cannot_leak_token(self):
        result, _ = self.execute(
            RuntimeError(f"transport exposed {self.token}"),
            "github_read_repo",
            owner="octo",
            repo="demo",
        )
        self.assertEqual(result.status, "executor_error")
        self.assertNotIn(self.token, result.error)


if __name__ == "__main__":
    unittest.main()
