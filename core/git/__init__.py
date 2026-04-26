"""Git operations — sandbox-routed clone + URL allowlist.

Two public entry points:

  - ``validate_repo_url(url)``: regex allowlist for github / gitlab
    HTTPS + SSH URLs. Designed to fail-closed: anything not matching
    is rejected.

  - ``clone_repository(url, target, depth=1)``: shallow clone routed
    through ``core.sandbox.run_untrusted`` with the egress proxy
    pinned to the github / gitlab hostnames. Equivalent to the
    semantics ``packages/static-analysis/scanner.py:safe_clone`` had
    pre-centralisation (and which scanner.py now imports from here).

The sandbox routing is the security-load-bearing piece. Pre-#210 this
module would have been a plain subprocess wrapper; post-#210 every
clone of an untrusted URL passes through namespace + Landlock + a
network namespace pinned to a hostname allowlist. ``git`` itself runs
as the untrusted process — a malicious server-side hook on a forked
clone (or a compromised mirror) is contained.
"""

from __future__ import annotations

from core.git.clone import clone_repository, get_safe_git_env
from core.git.validate import validate_repo_url

__all__ = [
    "clone_repository",
    "get_safe_git_env",
    "validate_repo_url",
]
