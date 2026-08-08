from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from agentgate.executors.filesystem import FileSystemExecutor


class TestFileSystemExecutor(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "sandbox"
        self.root.mkdir()
        (self.root / "public").mkdir()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_reads_utf8_file_with_pathlib(self):
        (self.root / "public" / "readme.txt").write_text("hello AgentGate", encoding="utf-8")
        result = FileSystemExecutor(self.root).execute("FILE_READ", {"path": "public/readme.txt"})
        self.assertTrue(result.success)
        self.assertEqual(result.data["content"], "hello AgentGate")
        self.assertEqual(result.data["path"], "public/readme.txt")

    def test_parent_traversal_is_blocked(self):
        result = FileSystemExecutor(self.root).execute("FILE_READ", {"path": "../outside.txt"})
        self.assertFalse(result.success)
        self.assertEqual(result.status, "sandbox_violation")

    def test_absolute_escape_is_blocked(self):
        outside = Path(self.tempdir.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        result = FileSystemExecutor(self.root).execute("FILE_READ", {"path": str(outside.resolve())})
        self.assertEqual(result.status, "sandbox_violation")

    def test_windows_drive_escape_is_blocked_cross_platform(self):
        result = FileSystemExecutor(self.root).execute("FILE_READ", {"path": r"C:\secrets\token.txt"})
        self.assertEqual(result.status, "sandbox_violation")

    def test_symlink_escape_is_blocked(self):
        outside = Path(self.tempdir.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.root / "public" / "outside-link.txt"
        try:
            link.symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        result = FileSystemExecutor(self.root).execute("FILE_READ", {"path": "public/outside-link.txt"})
        self.assertEqual(result.status, "sandbox_violation")

    def test_missing_file_is_controlled(self):
        result = FileSystemExecutor(self.root).execute("FILE_READ", {"path": "public/missing.txt"})
        self.assertEqual(result.status, "not_found")
        self.assertIsNotNone(result.error)

    def test_oversized_file_is_rejected(self):
        (self.root / "public" / "large.txt").write_bytes(b"12345")
        result = FileSystemExecutor(self.root, max_bytes=4).execute(
            "FILE_READ", {"path": "public/large.txt"}
        )
        self.assertEqual(result.status, "file_too_large")

    def test_binary_file_is_rejected(self):
        (self.root / "public" / "image.bin").write_bytes(b"abc\x00def")
        result = FileSystemExecutor(self.root).execute("FILE_READ", {"path": "public/image.bin"})
        self.assertEqual(result.status, "unsupported_content")


if __name__ == "__main__":
    unittest.main()
