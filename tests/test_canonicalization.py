"""Canonical form and digest stability."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from oat.canonical import CANONICAL_FORM, canonical_bytes, canonical_text, strip_noncanonical
from oat.digest import digest_bytes, digest_file, digest_object, digest_source_tree


def test_key_order_does_not_change_canonical_bytes() -> None:
    assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})


def test_canonical_bytes_are_compact_and_sorted() -> None:
    assert canonical_bytes({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'
    assert canonical_text({"a": 1}) == '{"a":1}'


def test_runtime_subtree_is_outside_the_digest_domain() -> None:
    with_runtime = {"a": 1, "runtime": {"python_version": "3.11.0", "host": "somewhere"}}
    without = {"a": 1}
    assert digest_object(with_runtime) == digest_object(without)


def test_runtime_is_stripped_recursively_including_inside_lists() -> None:
    value = {"items": [{"x": 1, "runtime": {"drop": True}}], "runtime": {"drop": True}}
    assert strip_noncanonical(value) == {"items": [{"x": 1}]}


def test_non_dict_values_pass_through_strip() -> None:
    assert strip_noncanonical("text") == "text"
    assert strip_noncanonical(7) == 7
    assert strip_noncanonical(None) is None


def test_non_ascii_survives_canonicalization() -> None:
    assert canonical_text({"k": "café"}) == '{"k":"café"}'


def test_nan_is_refused() -> None:
    with pytest.raises(ValueError):
        canonical_bytes({"x": math.nan})


def test_digests_are_prefixed_sha256() -> None:
    digest = digest_bytes(b"")
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


def test_digest_file_matches_digest_of_its_bytes(tmp_path: Path) -> None:
    path = tmp_path / "sample.json"
    path.write_bytes(b'{"a":1}')
    assert digest_file(path) == digest_bytes(b'{"a":1}')


def test_source_tree_digest_is_stable_and_content_sensitive(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n")
    (tmp_path / "pkg" / "__pycache__").mkdir()
    (tmp_path / "pkg" / "__pycache__" / "a.py").write_text("ignored\n")
    first = digest_source_tree(tmp_path)
    assert first == digest_source_tree(tmp_path)

    (tmp_path / "pkg" / "a.py").write_text("x = 2\n")
    assert digest_source_tree(tmp_path) != first


def test_canonical_form_is_declared() -> None:
    assert CANONICAL_FORM == "oat-canonical-json/1"
