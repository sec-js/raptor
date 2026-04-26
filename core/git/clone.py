"""Sandbox-routed git clone.

Wraps ``git clone`` in ``core.sandbox.run_untrusted`` with:

  - the egress proxy pinned to the small set of hostnames the URL
    allowlist permits (github.com / gitlab.com plus the known
    object-storage CDNs they redirect to);
  - landlocked filesystem so the clone process can only write into
    the target directory;
  - sanitised env (``RaptorConfig.get_git_env()`` — clears
    HTTP_PROXY / NO_PROXY etc., sets GIT_TERMINAL_PROMPT=0 and
    GIT_ASKPASS=true so a malformed-credential prompt can't hang
    the run);
  - bounded timeout (``RaptorConfig.GIT_CLONE_TIMEOUT``).

Pre-#210, scanner.py and recon/agent.py both implemented variants of
this. Post-centralisation everyone calls through here.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional

from core.config import RaptorConfig
from core.git.validate import validate_repo_url

logger = logging.getLogger(__name__)


# Egress allowlist for the sandbox network namespace. github.com /
# gitlab.com plus the CDN hosts they redirect to on clone (LFS, object
# storage). Add a host here only when the URL allowlist in
# ``validate.py`` also allows it — the two lists must stay coupled.
_PROXY_HOSTS = (
    "github.com", "gitlab.com",
    "codeload.github.com", "objects.githubusercontent.com",
)


def get_safe_git_env() -> Dict[str, str]:
    """Sanitised env for git subprocess. Same shape as scanner.py used
    pre-centralisation; promoted here so all callers share it."""
    return RaptorConfig.get_git_env()


def clone_repository(
    url: str, target: Path, depth: Optional[int] = 1,
) -> bool:
    """Shallow-clone ``url`` into ``target`` via the sandboxed runner.

    Args:
        url: must pass ``validate_repo_url``; rejected otherwise.
        target: destination directory. The sandbox is configured with
            this as the only writable path.
        depth: shallow-clone depth (default 1). Pass ``None`` to clone
            full history.

    Raises:
        ValueError: URL fails the allowlist.
        RuntimeError: ``git clone`` exited non-zero.
    """
    if not validate_repo_url(url):
        raise ValueError(f"Invalid or untrusted repository URL: {url}")

    cmd = ["git", "clone"]
    if depth is not None:
        cmd.extend(["--depth", str(depth), "--no-tags"])
    cmd.extend([url, str(target)])

    logger.info("git clone: %s -> %s", url, target)
    try:
        from core.sandbox import run_untrusted
    except ImportError:
        raise RuntimeError(
            "core.sandbox unavailable - git clone refuses to run "
            "without sandbox isolation"
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    proc = run_untrusted(
        cmd,
        target=str(target.parent),
        output=str(target.parent),
        env=get_safe_git_env(),
        proxy_hosts=list(_PROXY_HOSTS),
        timeout=RaptorConfig.GIT_CLONE_TIMEOUT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise RuntimeError(
            f"git clone failed: {stderr or stdout or 'unknown error'}"
        )
    return True


__all__ = ["clone_repository", "get_safe_git_env"]
