"""URL-allowlist tests."""

from core.git.validate import validate_repo_url


def test_github_https_accepted() -> None:
    assert validate_repo_url("https://github.com/torvalds/linux")
    assert validate_repo_url("https://github.com/torvalds/linux/")
    assert validate_repo_url("https://github.com/foo-bar/baz_qux.git")


def test_gitlab_https_accepted() -> None:
    assert validate_repo_url("https://gitlab.com/foo/bar")


def test_ssh_form_accepted() -> None:
    assert validate_repo_url("git@github.com:foo/bar.git")
    assert validate_repo_url("git@gitlab.com:foo/bar.git")


def test_other_hosts_rejected() -> None:
    assert not validate_repo_url("https://bitbucket.org/foo/bar")
    assert not validate_repo_url("https://example.com/repo")
    assert not validate_repo_url("https://github.com.evil.com/foo/bar")


def test_protocol_smuggling_rejected() -> None:
    """Allowlist regex anchors prevent prefix-smuggling attacks."""
    assert not validate_repo_url("ftp://github.com/foo/bar")
    assert not validate_repo_url("file:///etc/passwd")
    assert not validate_repo_url("https://github.com/foo/bar; rm -rf /")


def test_empty_or_malformed_rejected() -> None:
    assert not validate_repo_url("")
    assert not validate_repo_url("not a url")
    assert not validate_repo_url("https://github.com")     # no path
    assert not validate_repo_url("https://github.com/foo")  # no repo
