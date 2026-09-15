"""Licensing consistency.

The repository carries three separate grants — BSL 1.1 for code, CC BY 4.0
for documentation and specifications, and no grant at all for the marks and
the claim-bearing designation. This suite fails if any of them goes missing,
if stale "this is Apache licensed" language survives anywhere, or if the
packaging metadata implies OSI-approved open source.
"""

from __future__ import annotations

from pathlib import Path

import pytest

TEXT_SUFFIXES = {".py", ".md", ".json", ".yml", ".yaml", ".toml", ".cfg", ".txt"}
EXTENSIONLESS = {"Makefile"}

#: An "Apache" mention is legitimate only as the BSL *Change* License — the
#: license this code becomes later — never as the license it is under now.
FUTURE_LICENSE_CONTEXT = (
    "change license",
    "change date",
    "changes to apache",
    "becomes the apache",
    "converts to apache",
)

#: Phrases that assert Apache as the present license, in any file.
STALE_PRESENT_TENSE = (
    "licensed under the apache",
    "licensed under apache",
    "is licensed under the apache license",
    "apache-2.0. see",
    "spdx-license-identifier: apache",
    'license = { text = "apache',
    "license: apache",
)


def flowed(text: str) -> str:
    """Collapse whitespace so assertions survive hard-wrapped prose."""
    return " ".join(text.split())


def tracked_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in EXTENSIONLESS:
            files.append(path)
    return files


def test_no_stale_apache_present_license_language(repo_root: Path) -> None:
    """Every Apache mention must be the future Change License, not the current one."""
    offenders: list[str] = []
    for path in tracked_text_files(repo_root):
        if path.name == Path(__file__).name:
            continue
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1
        ):
            lowered = line.lower()
            if any(phrase in lowered for phrase in STALE_PRESENT_TENSE):
                offenders.append(f"{path.relative_to(repo_root)}:{number}: {line.strip()}")
                continue
            if "apache" in lowered and not any(
                marker in lowered for marker in FUTURE_LICENSE_CONTEXT
            ):
                offenders.append(f"{path.relative_to(repo_root)}:{number}: {line.strip()}")
    assert not offenders, "stale or unqualified Apache licensing language:\n" + "\n".join(offenders)


def test_the_three_license_documents_exist(repo_root: Path) -> None:
    for name in ("LICENSE.md", "LICENSE-DOCS.md", "TRADEMARKS-AND-STANDING.md"):
        assert (repo_root / name).is_file(), f"{name} is missing"


def test_code_license_is_bsl_with_the_approved_parameters(repo_root: Path) -> None:
    text = (repo_root / "LICENSE.md").read_text(encoding="utf-8")
    prose = flowed(text).lower()

    assert "Business Source License 1.1" in text
    assert "Change Date:          2030-09-15" in text
    assert "Change License:       Apache License, Version 2.0" in text
    # BSL is explicit that it is not an Open Source license; so are we.
    assert "not an Open Source license" in text
    # The Additional Use Grant must name every owner-approved use.
    for granted in (
        "research",
        "independent reproduction",
        "internal evaluation",
        "benchmarking",
        "security testing",
        "non-production enterprise pilots",
    ):
        assert granted in prose, f"Additional Use Grant does not mention {granted!r}"
    # ...and the reserved commercial uses must be named as not granted.
    for reserved in (
        "production deployment",
        "paid assurance or certification services",
        "managed OAT services",
        "resale",
    ):
        assert reserved.lower() in prose, f"reserved use not named: {reserved!r}"


def test_docs_license_is_cc_by_40_with_a_stated_scope(repo_root: Path) -> None:
    text = (repo_root / "LICENSE-DOCS.md").read_text(encoding="utf-8")

    assert "Creative Commons Attribution 4.0 International" in text
    assert "SPDX-License-Identifier: CC-BY-4.0" in text
    for scoped in ("docs/", "schemas/", "README.md"):
        assert scoped in text, f"CC BY scope does not mention {scoped!r}"
    # The code must be explicitly carved out of the documentation grant.
    assert "Business Source License 1.1" in text


def test_marks_and_standing_are_reserved(repo_root: Path) -> None:
    text = (repo_root / "TRADEMARKS-AND-STANDING.md").read_text(encoding="utf-8")

    prose = flowed(text)
    for reserved in ("certification", "accreditation", "claim-bearing OAT status"):
        assert reserved in prose, f"standing notice does not reserve {reserved!r}"
    assert "does not grant you any right in any trademark" in prose
    assert "CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE" in text


def test_packaging_metadata_does_not_imply_open_source(repo_root: Path) -> None:
    """Read as text: ``tomllib`` is 3.11+, and this must hold on 3.10 too."""
    text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")

    assert 'license = { text = "BUSL-1.1" }' in text
    assert '"License :: Other/Proprietary License",' in text
    assert "OSI Approved" not in text, (
        "an OSI Approved classifier would falsely imply open-source licensing"
    )
    assert '"Private :: Do Not Upload",' in text


@pytest.mark.parametrize(
    "document",
    ["LICENSE.md", "LICENSE-DOCS.md", "TRADEMARKS-AND-STANDING.md", "README.md"],
)
def test_licensing_documents_preserve_the_quarantine(document: str, repo_root: Path) -> None:
    """A licensing change must never read as a grant of standing."""
    text = (repo_root / document).read_text(encoding="utf-8")
    assert "CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE" in text


def test_readme_distinguishes_the_three_grants(repo_root: Path) -> None:
    text = (repo_root / "README.md").read_text(encoding="utf-8")

    assert "Business Source License 1.1" in text
    assert "CC BY 4.0" in text
    assert "LICENSE-DOCS.md" in text
    assert "TRADEMARKS-AND-STANDING.md" in text
    assert "not an Open Source license" in text
