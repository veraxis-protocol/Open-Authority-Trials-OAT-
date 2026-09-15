"""Immutable OAT/subject/config binding checks."""

from __future__ import annotations

import subprocess
from pathlib import Path


class BindingError(RuntimeError):
    pass


def git_identity(path: str | Path) -> dict[str, str]:
    root = Path(path)

    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

    return {
        "head": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "status": git("status", "--porcelain=v1"),
    }


def require_git_identity(path: str | Path, *, head: str, tree: str) -> None:
    actual = git_identity(path)
    if actual["status"]:
        raise BindingError(f"subject mutation detected: {Path(path).name}")
    if actual["head"] != head or actual["tree"] != tree:
        raise BindingError(f"wrong frozen identity: {Path(path).name}")


def require_digest(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        raise BindingError(f"wrong {label} binding")
