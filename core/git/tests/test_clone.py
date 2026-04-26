"""Clone-wrapper tests - subprocess + sandbox stubbed."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from core.git.clone import clone_repository


def _completed(rc: int, stderr: str = "",
               stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=rc, stdout=stdout, stderr=stderr,
    )


def test_invalid_url_raises_before_subprocess(tmp_path: Path) -> None:
    """URL that fails allowlist must NOT reach the sandboxed runner."""
    with patch("core.sandbox.run_untrusted") as mock_run:
        with pytest.raises(ValueError):
            clone_repository("https://evil.example.com/repo",
                              tmp_path / "out")
        mock_run.assert_not_called()


def test_successful_clone_calls_sandbox(tmp_path: Path) -> None:
    """Allowlisted URL flows through ``run_untrusted`` with the right
    flags - depth, no-tags, target/output set, proxy hosts pinned."""
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        ok = clone_repository(
            "https://github.com/foo/bar", tmp_path / "out",
        )
        assert ok is True
        assert mock_run.called
        cmd = mock_run.call_args.args[0]
        assert cmd[:4] == ["git", "clone", "--depth", "1"]
        kwargs = mock_run.call_args.kwargs
        assert "github.com" in kwargs.get("proxy_hosts", [])
        assert "codeload.github.com" in kwargs.get("proxy_hosts", [])


def test_clone_failure_raises_runtime_error(tmp_path: Path) -> None:
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(128, stderr="fatal: not found")
        with pytest.raises(RuntimeError, match="not found"):
            clone_repository("https://github.com/foo/bar",
                              tmp_path / "out")


def test_full_clone_drops_depth_flag(tmp_path: Path) -> None:
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        clone_repository("https://github.com/foo/bar",
                          tmp_path / "out", depth=None)
        cmd = mock_run.call_args.args[0]
        assert "--depth" not in cmd
        assert "--no-tags" not in cmd
