from __future__ import annotations

import pytest

from oat.veip.binding import BindingError, require_digest, require_git_identity


def test_wrong_runtime_digest_aborts():
    require_digest("x", "x", "seed/config/prompt")
    with pytest.raises(BindingError, match="wrong seed/config/prompt"):
        require_digest("x", "y", "seed/config/prompt")


def test_subject_mutation_and_wrong_identity_abort(monkeypatch):
    monkeypatch.setattr(
        "oat.veip.binding.git_identity",
        lambda _path: {"head": "h", "tree": "t", "status": "changed.py"},
    )
    with pytest.raises(BindingError, match="subject mutation"):
        require_git_identity("subject", head="h", tree="t")
    monkeypatch.setattr(
        "oat.veip.binding.git_identity",
        lambda _path: {"head": "wrong", "tree": "t", "status": ""},
    )
    with pytest.raises(BindingError, match="wrong frozen identity"):
        require_git_identity("subject", head="h", tree="t")
