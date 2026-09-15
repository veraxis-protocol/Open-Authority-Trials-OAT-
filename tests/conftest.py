"""Shared fixtures. Tests never reach the network and never read a clock."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = REPO_ROOT / "scenarios" / "rb001"
REFERENCE_RUN = REPO_ROOT / "examples" / "rb001" / "reference-run"


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def scenario_dir() -> Path:
    return SCENARIO_DIR


@pytest.fixture
def at_repo_root(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Run inside the repository root so relative scenario references resolve."""
    monkeypatch.chdir(REPO_ROOT)
    yield REPO_ROOT


def scenario_path(name: str) -> Path:
    return SCENARIO_DIR / f"{name}.json"
