"""Digest helpers. Every digest in OAT is a prefixed SHA-256 hex string."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from oat.canonical import canonical_bytes

DIGEST_ALGORITHM: str = "sha256"


def digest_bytes(data: bytes) -> str:
    """Return ``sha256:<hex>`` for raw bytes."""
    return f"{DIGEST_ALGORITHM}:{hashlib.sha256(data).hexdigest()}"


def digest_object(value: Any) -> str:
    """Return the digest of the canonical encoding of ``value``."""
    return digest_bytes(canonical_bytes(value))


def digest_file(path: str | Path) -> str:
    """Return the digest of a file's exact bytes."""
    return digest_bytes(Path(path).read_bytes())


def digest_source_tree(root: str | Path, suffixes: tuple[str, ...] = (".py",)) -> str:
    """Return a stable identity digest for a source tree.

    Files are ordered by POSIX-relative path so the result does not depend on
    directory iteration order or on where the tree is checked out.
    """
    root_path = Path(root)
    entries: list[dict[str, str]] = []
    for file_path in sorted(root_path.rglob("*")):
        if not file_path.is_file() or file_path.suffix not in suffixes:
            continue
        if "__pycache__" in file_path.parts:
            continue
        entries.append(
            {
                "path": file_path.relative_to(root_path).as_posix(),
                "digest": digest_file(file_path),
            }
        )
    return digest_object({"tree": entries})
