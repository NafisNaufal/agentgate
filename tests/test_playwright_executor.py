from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from agentgate.executors.playwright import PlaywrightExecutor
from agentgate.schemas import ActionRequest


class FakeLocator:
    def __init__(
        self,
        tag: str = "button",
        *,
        role: str = "button",
        type_name: str = "submit",
        label: str = "Send Message",
        text: str = "Send Message",
    ) -> None:
        self.tag = tag
        self.fingerprint = {
            "role": role,
            "type": type_name,
            "label": label,
            "text": text,
            "href": "",
            "form_action": "",
            "method": "",
            "disabled": False,
        }
        self.clicked = 0
        self.filled: list[str] = []
        self.selected: list[Any] = []
        self.visible = True

    def is_visible(self, timeout: int) -> bool:
        return self.visible

    def count(self) -> int:
        return 1

    def element_handle(self) -> "FakeLocator":
        return self

    def click(self, timeout: int) -> None:
        self.clicked += 1

    def fill(self, value: str, timeout: int) -> None:
        self.filled.append(value)

    def select_option(self, option: Any, timeout: int) -> None:
        self.selected.append(option)

    def evaluate(self, script: str) -> str | None:
        if "const labels" in script:
            return self.fingerprint
        if "tagName" in script:
            return self.tag
        self.clicked += 1
        return None


class FakeCollection:
    def __init__(self, locators: list[FakeLocator]) -> None:
        self.locators = locators

    def nth(self, index: int) -> FakeLocator:
        return self.locators[index]


class FakePage:
    def __init__(self) -> None:
        self.url = "http://localhost/form"
        self.locators = [
            FakeLocator("button"),
            FakeLocator(
                "input",
                role="textbox",
                type_name="password",
                label="Password",
                text="",
            ),
        ]
        self.goto_calls: list[str] = []
        self.screenshot_paths: list[str] = []
        self.closed = False

    def is_closed(self) -> bool:
        return self.closed

    def title(self) -> str:
        return "Mock form"

    def goto(self, url: str, **kwargs: Any) -> None:
        self.goto_calls.append(url)
        self.url = url

    def evaluate(self, script: str, snapshot_token: str | None = None) -> dict[str, Any]:
        snapshot_token = snapshot_token or "snapshot"
        return {
            "visible_text": "Welcome. Send Message",
            "elements": [
                {"marker": f"{snapshot_token}-0", "role": "button", "type": "submit", "label": "Send Message", "text": "Send Message", "value": "", "href": "", "form_action": "", "method": "", "disabled": False},
                {"marker": f"{snapshot_token}-1", "role": "textbox", "type": "password", "label": "Password", "text": "", "value": "secret-value", "href": "", "form_action": "", "method": "", "disabled": False},
            ],
        }

    def locator(self, selector: str) -> FakeCollection | FakeLocator:
        if "data-agentgate-id" in selector:
            return self.locators[0 if selector.endswith('-0"]') else 1]
        return FakeCollection(self.locators)

    def screenshot(self, path: str, **kwargs: Any) -> None:
        self.screenshot_paths.append(path)
        Path(path).write_bytes(b"fake-png")


class TestPlaywrightExecutor(unittest.TestCase):
    def setUp(self) -> None:
        self.page = FakePage()
        self.tempdir = tempfile.TemporaryDirectory()
        self.executor = PlaywrightExecutor(
            page=self.page,
            allowed_origins="http://localhost,http://127.0.0.1",
            screenshot_dir=self.tempdir.name,
            allow_injected_page_for_tests=True,
        )

    def tearDown(self) -> None:
        self.executor.close()
        self.tempdir.cleanup()

    def test_simplified_snapshot_shape_and_selector_map(self):
        result = self.executor.execute("BROWSER_SNAPSHOT", {})
        self.assertTrue(result.success)
        self.assertEqual(
            set(result.data),
            {"url", "title", "visible_text", "interactive_elements"},
        )
        elements = result.data["interactive_elements"]
        self.assertEqual(elements[0]["element_id"], "1")
        self.assertEqual(elements[0]["role"], "button")
        self.assertIn("external_send", elements[0]["risk_hint"])
        self.assertIn("form_submit", elements[0]["risk_hint"])
        self.assertEqual(elements[1]["value_preview"], "[REDACTED]")
        self.assertNotIn("html", result.data)
        self.assertEqual(set(self.executor._selector_map), {"1", "2"})

    def test_snapshot_risk_metadata_enriches_guardrail_request(self):
        self.executor.execute("BROWSER_SNAPSHOT", {})
        request = self.executor.enrich_request(
            ActionRequest(action_type="BROWSER_SUBMIT", target="1"),
            {"element_id": "1"},
        )
        self.assertIn("external_send", request.risk_hint)
        self.assertIn("Send Message", request.content_context)

    def test_link_destination_is_trusted_risk_context(self):
        original_evaluate = self.page.evaluate

        def evaluate_with_destination(script: str, snapshot_token: str | None = None):
            snapshot = original_evaluate(script, snapshot_token)
            snapshot["elements"][0]["href"] = "http://localhost/delete-account"
            self.page.locators[0].fingerprint["href"] = "http://localhost/delete-account"
            return snapshot

        self.page.evaluate = evaluate_with_destination
        self.executor.execute("BROWSER_SNAPSHOT", {})
        request = self.executor.enrich_request(
            ActionRequest(action_type="BROWSER_CLICK", target="1"),
            {"element_id": "1"},
        )
        self.assertIn("destructive_action", request.risk_hint)
        self.assertFalse(request.rollback_available)
        self.assertIn("delete-account", request.content_context)

    def test_submit_control_cannot_execute_as_click(self):
        self.executor.execute("BROWSER_SNAPSHOT", {})
        result = self.executor.execute("BROWSER_CLICK", {"element_id": "1"})
        self.assertFalse(result.success)
        self.assertEqual(result.status, "submit_requires_guarded_action")
        self.assertEqual(self.page.locators[0].clicked, 0)

    def test_image_submit_cannot_execute_as_click(self):
        original_evaluate = self.page.evaluate

        def evaluate_image_submit(script: str, snapshot_token: str | None = None):
            snapshot = original_evaluate(script, snapshot_token)
            snapshot["elements"][0]["type"] = "image"
            snapshot["elements"][0]["role"] = "submit"
            self.page.locators[0].fingerprint["type"] = "image"
            self.page.locators[0].fingerprint["role"] = "submit"
            return snapshot

        self.page.evaluate = evaluate_image_submit
        self.executor.execute("BROWSER_SNAPSHOT", {})
        result = self.executor.execute("BROWSER_CLICK", {"element_id": "1"})
        self.assertFalse(result.success)
        self.assertEqual(result.status, "submit_requires_guarded_action")

    def test_type_uses_mapped_element(self):
        self.executor.execute("BROWSER_SNAPSHOT", {})
        result = self.executor.execute(
            "BROWSER_TYPE", {"element_id": "2", "value": "Contact [REDACTED_EMAIL]"}
        )
        self.assertTrue(result.success)
        self.assertEqual(self.page.locators[1].filled, ["Contact [REDACTED_EMAIL]"])

    def test_unknown_element_id_is_controlled(self):
        result = self.executor.execute("BROWSER_CLICK", {"element_id": "99"})
        self.assertFalse(result.success)
        self.assertEqual(result.status, "stale_element")

    def test_changed_element_fingerprint_is_stale(self):
        self.executor.execute("BROWSER_SNAPSHOT", {})
        self.page.locators[0].fingerprint["text"] = "Delete Account"
        result = self.executor.execute("BROWSER_CLICK", {"element_id": "1"})
        self.assertEqual(result.status, "stale_element")

    def test_disallowed_host_does_not_navigate(self):
        result = self.executor.execute("BROWSER_OPEN", {"url": "https://example.com"})
        self.assertEqual(result.status, "url_not_allowed")
        self.assertEqual(self.page.goto_calls, [])

    def test_same_host_different_port_is_not_allowed(self):
        result = self.executor.execute("BROWSER_OPEN", {"url": "http://localhost:9999"})
        self.assertEqual(result.status, "url_not_allowed")
        self.assertEqual(self.page.goto_calls, [])

    def test_allowed_host_opens_page(self):
        result = self.executor.execute("BROWSER_OPEN", {"url": "http://localhost/next"})
        self.assertTrue(result.success)
        self.assertEqual(self.page.goto_calls, ["http://localhost/next"])

    def test_select_uses_mapped_element(self):
        self.executor.execute("BROWSER_SNAPSHOT", {})
        result = self.executor.execute("BROWSER_SELECT", {"element_id": "2", "option": "safe"})
        self.assertTrue(result.success)
        self.assertEqual(self.page.locators[1].selected, ["safe"])

    def test_submit_uses_mapped_element(self):
        self.executor.execute("BROWSER_SNAPSHOT", {})
        result = self.executor.execute("BROWSER_SUBMIT", {"element_id": "1"})
        self.assertTrue(result.success)
        self.assertEqual(self.page.locators[0].clicked, 1)

    def test_missing_playwright_dependency_is_controlled(self):
        def missing_factory():
            raise ImportError("playwright unavailable")

        executor = PlaywrightExecutor(playwright_factory=missing_factory)
        result = executor.execute("BROWSER_SNAPSHOT", {})
        self.assertFalse(result.success)
        self.assertEqual(result.status, "dependency_missing")

    def test_injected_page_requires_explicit_test_mode(self):
        executor = PlaywrightExecutor(page=FakePage())
        result = executor.execute("BROWSER_SNAPSHOT", {})
        self.assertEqual(result.status, "injected_page_not_allowed")

    def test_screenshot_path_is_generated_inside_controlled_directory(self):
        result = self.executor.execute("BROWSER_SCREENSHOT", {"path": "/tmp/ignored.png"})
        screenshot = Path(result.data["path"])
        self.assertTrue(result.success)
        self.assertEqual(screenshot.parent, Path(self.tempdir.name).resolve())
        self.assertNotEqual(str(screenshot), "/tmp/ignored.png")


if __name__ == "__main__":
    unittest.main()
