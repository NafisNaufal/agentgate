"""Sandboxed local UTF-8 file reader."""

from __future__ import annotations

import os
import errno
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from .base import ExecutionResult


_DEFAULT_MAX_BYTES = 1_048_576


class FileSystemExecutor:
    """Execute FILE_READ without permitting paths outside a configured sandbox."""

    def __init__(
        self,
        sandbox_root: str | Path | None = None,
        max_bytes: int | None = None,
    ) -> None:
        configured_root = sandbox_root or os.environ.get("AGENTGATE_SANDBOX_ROOT", "./sandbox")
        self.sandbox_root = Path(configured_root).expanduser().resolve()
        if max_bytes is None:
            raw_max = os.environ.get("AGENTGATE_FILE_MAX_BYTES", str(_DEFAULT_MAX_BYTES))
            try:
                max_bytes = int(raw_max)
            except ValueError:
                max_bytes = _DEFAULT_MAX_BYTES
        self.max_bytes = max_bytes if max_bytes > 0 else _DEFAULT_MAX_BYTES

    def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
        if action_type != "FILE_READ":
            return self._failure("unsupported_action", "Filesystem executor only supports FILE_READ")

        raw_path = arguments.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            return self._failure("invalid_arguments", "FILE_READ requires a relative path")

        try:
            path, relative = self._resolve_path(raw_path)
        except ValueError as exc:
            return self._failure("sandbox_violation", str(exc))

        try:
            raw = self._read_bounded(relative, path)
        except FileNotFoundError:
            return self._failure("not_found", "File does not exist inside the sandbox")
        except (IsADirectoryError, _NotRegularFile):
            return self._failure("not_a_file", "Requested path is not a regular file")
        except _FileTooLarge:
            return self._failure(
                "file_too_large",
                f"File exceeds the configured {self.max_bytes}-byte limit",
            )
        except _SymlinkViolation:
            return self._failure("sandbox_violation", "Symlinks are not allowed in FILE_READ paths")
        except PermissionError:
            return self._failure("permission_denied", "Permission denied while reading the file")
        except OSError as exc:
            return self._failure("filesystem_error", f"Unable to read file: {exc}")

        if b"\x00" in raw:
            return self._failure("unsupported_content", "Binary files are not supported")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            return self._failure("unsupported_content", "File is not valid UTF-8 text")

        relative_path = relative.as_posix()
        return ExecutionResult(
            success=True,
            status="success",
            summary=f"Read {relative_path}",
            data={"path": relative_path, "size_bytes": len(raw), "content": content},
        )

    def _resolve_path(self, raw_path: str) -> tuple[Path, Path]:
        native = Path(raw_path.replace("\\", os.sep))
        windows = PureWindowsPath(raw_path)
        portable = PurePosixPath(raw_path.replace("\\", "/"))
        if native.is_absolute() or windows.is_absolute() or windows.drive:
            raise ValueError("Absolute filesystem paths are not allowed")
        if ".." in native.parts or ".." in windows.parts or ".." in portable.parts:
            raise ValueError("Parent-directory traversal is not allowed")

        candidate = (self.sandbox_root / native).resolve()
        try:
            candidate.relative_to(self.sandbox_root)
        except ValueError as exc:
            raise ValueError("Requested path resolves outside the sandbox") from exc
        return candidate, native

    def _read_bounded(self, relative: Path, resolved: Path) -> bytes:
        if (
            os.name == "posix"
            and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd
        ):
            return self._read_bounded_posix(relative)
        if os.name == "nt":
            return self._read_bounded_windows(resolved)

        with resolved.open("rb") as handle:
            final_path = resolved.resolve()
            try:
                final_path.relative_to(self.sandbox_root)
            except ValueError as exc:
                raise _SymlinkViolation from exc
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise _NotRegularFile
            raw = handle.read(self.max_bytes + 1)
        if len(raw) > self.max_bytes:
            raise _FileTooLarge
        return raw

    def _read_bounded_windows(self, resolved: Path) -> bytes:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        descriptor = os.open(resolved, os.O_RDONLY | os.O_BINARY)
        try:
            handle = msvcrt.get_osfhandle(descriptor)
            get_final_path = ctypes.windll.kernel32.GetFinalPathNameByHandleW
            get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            get_final_path.restype = wintypes.DWORD
            needed = get_final_path(handle, None, 0, 0)
            if not needed:
                raise OSError(ctypes.get_last_error(), "Unable to resolve opened file handle")
            buffer = ctypes.create_unicode_buffer(needed + 1)
            if not get_final_path(handle, buffer, len(buffer), 0):
                raise OSError(ctypes.get_last_error(), "Unable to resolve opened file handle")
            final_path = buffer.value
            if final_path.startswith("\\\\?\\UNC\\"):
                final_path = "\\\\" + final_path[8:]
            elif final_path.startswith("\\\\?\\"):
                final_path = final_path[4:]
            final_normalized = os.path.normcase(os.path.abspath(final_path))
            root_normalized = os.path.normcase(os.path.abspath(self.sandbox_root))
            try:
                confined = os.path.commonpath((final_normalized, root_normalized)) == root_normalized
            except ValueError:
                confined = False
            if not confined:
                raise _SymlinkViolation
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise _NotRegularFile
            chunks: list[bytes] = []
            remaining = self.max_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > self.max_bytes:
                raise _FileTooLarge
            return raw
        finally:
            os.close(descriptor)

    def _read_bounded_posix(self, relative: Path) -> bytes:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        file_flags = os.O_RDONLY | os.O_NOFOLLOW
        descriptors: list[int] = []
        try:
            current = os.open(self.sandbox_root, directory_flags)
            descriptors.append(current)
            for index, part in enumerate(relative.parts):
                flags = file_flags if index == len(relative.parts) - 1 else directory_flags
                try:
                    current = os.open(part, flags, dir_fd=current)
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise _SymlinkViolation from exc
                    raise
                descriptors.append(current)
            if len(descriptors) == 1 or not stat.S_ISREG(os.fstat(current).st_mode):
                raise _NotRegularFile
            chunks: list[bytes] = []
            remaining = self.max_bytes + 1
            while remaining > 0:
                chunk = os.read(current, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > self.max_bytes:
                raise _FileTooLarge
            return raw
        finally:
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @staticmethod
    def _failure(status: str, error: str) -> ExecutionResult:
        return ExecutionResult(False, status, "Filesystem read was not completed", error=error)


class _NotRegularFile(Exception):
    pass


class _FileTooLarge(Exception):
    pass


class _SymlinkViolation(Exception):
    pass
