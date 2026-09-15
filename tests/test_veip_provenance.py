from __future__ import annotations

from types import SimpleNamespace

import pytest

import oat.veip.provenance as provenance
from oat.veip.provenance import ImportProvenanceError, record_import_provenance


def test_records_distribution_artifact_commit_and_isolated_path(monkeypatch, tmp_path):
    runtime = tmp_path / "runtime"
    installed = runtime / "Lib" / "site-packages" / "veip_sdk" / "__init__.py"
    installed.parent.mkdir(parents=True)
    installed.write_text("", encoding="utf-8")
    monkeypatch.setattr(provenance.importlib.metadata, "version", lambda _name: "0.1.0")
    monkeypatch.setattr(
        provenance.importlib,
        "import_module",
        lambda _name: SimpleNamespace(__file__=str(installed)),
    )

    result = record_import_provenance(
        modules={"veip_sdk": ("veip-sdk", "a" * 64, "b" * 40)},
        expected_runtime_root=runtime,
        forbidden_roots=[tmp_path / "subject"],
    )

    assert result["veip_sdk"] == {
        "module_file": str(installed.resolve()),
        "distribution": "veip-sdk",
        "version": "0.1.0",
        "artifact_sha256": "a" * 64,
        "frozen_source_commit": "b" * 40,
    }


@pytest.mark.parametrize("location", ["outside", "forbidden"])
def test_rejects_import_outside_runtime_or_from_subject(monkeypatch, tmp_path, location):
    runtime = tmp_path / "runtime"
    forbidden = runtime / "subject"
    module_path = (tmp_path / "elsewhere" if location == "outside" else forbidden) / "pkg.py"
    module_path.parent.mkdir(parents=True)
    module_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        provenance.importlib,
        "import_module",
        lambda _name: SimpleNamespace(__file__=str(module_path)),
    )

    with pytest.raises(ImportProvenanceError):
        record_import_provenance(
            modules={"pkg": ("pkg", "a" * 64, "b" * 40)},
            expected_runtime_root=runtime,
            forbidden_roots=[forbidden],
        )


def test_rejects_module_without_file(monkeypatch, tmp_path):
    monkeypatch.setattr(provenance.importlib, "import_module", lambda _name: object())
    with pytest.raises(ImportProvenanceError, match="no file provenance"):
        record_import_provenance(
            modules={"pkg": ("pkg", "a" * 64, "b" * 40)},
            expected_runtime_root=tmp_path,
            forbidden_roots=[],
        )
